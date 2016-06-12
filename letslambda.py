# -*- coding: utf-8 -*-

import base64
import boto3
import hashlib
import logging
import os
import requests
import yaml
from acme import challenges
from acme import client
from acme import errors
from acme import messages
from acme.jose.util import ComparableX509
from botocore.config import Config
from botocore.exceptions import ClientError
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from datetime import datetime
from OpenSSL import crypto
from time import sleep

LOG = logging.getLogger("letslambda")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
handler.setFormatter(formatter)
# add ch to logger
LOG.addHandler(handler)

def load_from_s3(conf, s3_key):
    """
    Try to load a file from the s3 bucket and return it as a string
    Return None on error
    """
    try:
        s3 = conf['s3_client']
        content = s3.get_object(Bucket=conf['s3_bucket'], Key=s3_key)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to load '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

    return content

def load_config(s3, s3_bucket, letslambda_config):
    """
    Try to load the letlambda.yml out of the user bucket
    Will return None if the configuration file does not exist
    """

    try:
        conf = s3.get_object(Bucket=s3_bucket, Key=letslambda_config)["Body"].read()
    except ClientError as e:
        LOG.error("Failed to fetch letslambda configuration '{0}' in bucket '{1}'".format(letslambda_config, s3_bucket))
        LOG.error("Error: {0}".format(e))
        return None

    return yaml.load(conf)

def load_letsencrypt_account_key(conf):
    """
    Try to load the RSA account key from S3. If it doesn't
    succeed, it will create a new account key and try a registration
    with your provided information
    The letsenrypt account key is needed to avoid redoing the Proof of
    Possession challenge (PoP). It is also used to revoke an existing
    certificate.
    """
    LOG.debug("Loading account key from s3")

    newAccountNeeded = False
    account_key = load_from_s3(conf, 'account.key.pem')
    if account_key == None:
        account_key = create_and_save_key(conf, "account.key.pem", conf['kms_key'])
        newAccountNeeded = True

    key = client.jose.JWKRSA.load(account_key)
    if newAccountNeeded:
        register_new_account(conf, key)

    return key

def register_new_account(conf, key):
    """
    Attempt to create a new account on the ACME server
    with the key. No problem if it fails because this
    kye is already used.
    """
    LOG.info("Registering with ACME server with the new account key")
    newReg = messages.NewRegistration(contact=tuple(conf['info']), key=key.public_key())
    acme_client = client.Client(conf['directory'], key)
    registration_resource = acme_client.register(newReg)
    LOG.info("Agreeing on the TOS on your behalf")
    acme_client.agree_to_tos(registration_resource)

def get_authorization(client, domain):
    authorization_resource = client.request_domain_challenges(domain['name'])
    return authorization_resource

def get_dns_challenge(authorization_resource):
    """
    Ask the ACME server to give us a list of challenges.
    Later, we will pick only the DNS one.
    """
    # Now let's look for a DNS challenge
    dns_challenges = filter(lambda x: isinstance(x.chall, challenges.DNS01), authorization_resource.body.challenges)
    return list(dns_challenges)[0]

def get_route53_zone_id(conf, zone_name):
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if zone_name.endswith('.') is not True:
        zone_name += '.'

    try:
        dn = ''
        zi = ''
        zone_list = r53.list_hosted_zones_by_name(DNSName=zone_name)
        while True:
            for zone in zone_list['HostedZones']:
                if zone['Name'] == zone_name:
                    return zone['Id']

            if zone_list['IsTruncated'] is not True:
                return None

            dn = zone_list['NextDNSName']
            zi = zone_list['NextHostedZoneId']

            LOG.debug("Continuing to fetch mode Route53 hosted zones...")
            zone_list = r53.list_hosted_zones_by_name(DNSName=dn, HostedZoneId=zi)

    except ClientError as e:
        LOG.error("Failed to retrieve Route53 zone Id for '{0}'".format(zone_name))
        LOG.error("Error: {0}".format(e))
        return None

    return None

def reset_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn):
    """
    Remove previous challenges from the hosted zone
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    rr_list = []
    results = r53.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordType='TXT',
                StartRecordName=rr_fqdn,
                MaxItems='100')

    while True:
        rr_list = rr_list + results['ResourceRecordSets']
        if results['IsTruncated'] == False:
            break

        results = r53.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordType='TXT',
            StartRecordName=results['NextRecordName'])

    r53_changes = { 'Changes': []}
    for rr in rr_list:
        if rr['Name'] == rr_fqdn and rr['Type'] == 'TXT':
            r53_changes['Changes'].append({
                'Action': 'DELETE',
                'ResourceRecordSet': {
                    'Name': rr['Name'],
                    'Type': rr['Type'],
                    'TTL': rr['TTL'],
                    'ResourceRecords': rr['ResourceRecords']
                }
            })
            try:
                res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
                LOG.info("Removed resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                return True

            except ClientError as e:
                LOG.error("Failed to remove resource record '{0}' from hosted zone '{1}'".format(rr_fqdn, zone_name))
                LOG.error("Error: {0}".format(e))
                return None

            break

    LOG.debug("No Resource Record to delete.")
    return False

def create_route53_letsencrypt_record(conf, zone_id, zone_name, rr_fqdn, rr_type, rr_value):
    """
    Create the required dns record for letsencrypt to verify
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    if rr_fqdn.endswith('.') is not True:
        rr_fqdn += '.'

    r53_changes = { 'Changes': [{
        'Action': 'CREATE',
        'ResourceRecordSet': {
            'Name': rr_fqdn,
            'Type': rr_type,
            'TTL': 60,
            'ResourceRecords': [{
                'Value': rr_value
            }]
        }
    }]}

    try:
        res = r53.change_resource_record_sets(HostedZoneId=zone_id, ChangeBatch=r53_changes)
        LOG.info("Create letsencrypt verification record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        return res

    except ClientError as e:
        LOG.error("Failed to create resource record '{0}' in hosted zone '{1}'".format(rr_fqdn, zone_name))
        LOG.error("Error: {0}".format(e))
        return None

def wait_letsencrypt_record_insync(conf, r53_status):
    """
    Wait until the new record set has been created
    """
    r53 = boto3.client('route53', config=Config(signature_version='v4', region_name=conf['region']))

    LOG.info("Waiting for DNS to synchronize with new TXT value")
    timeout = 60

    status = r53_status['ChangeInfo']['Status']
    while status != 'INSYNC':
        sleep(1)
        timeout = timeout-1
        try:
            r53_status = r53.get_change(Id=r53_status['ChangeInfo']['Id'])
            status = r53_status['ChangeInfo']['Status']

            if timeout == -1:
                return False

        except ClientError as e:
            LOG.error("Failed to retrieve record creation status.")
            LOG.error("Error: {0}".format(e))
            return None

    LOG.debug("Route53 synchronized in {0:d} seconds.".format(60-timeout))
    return True

def save_certificates_to_s3(conf, domain, chain_certificate, certificate):
    """
    Save/overwite newly requested certificate and corresponding chain certificate
    """
    if chain_certificate is not False:
        LOG.info("Saving certificate to S3")
        save_to_s3(conf, domain['name']+".chain.pem", chain_certificate)

    LOG.info("Saving chain certificate to S3")
    save_to_s3(conf, domain['name']+".cert.pem", certificate)


def upload_to_iam(conf, domain, chain_certificate, certificate, key):
    """
    Create a new IAM certificate from ACME and private key.
    It also fetched the chain certificate from ACME if provided
    """
    LOG.info("Loading certificate elements for domain '{0}' into IAM".format(domain['name']))

    iam = boto3.client('iam', config=Config(signature_version='v4', region_name=conf['region']))

    try:
        if chain_certificate == False:
            res = iam.upload_server_certificate(
                Path='/',
                ServerCertificateName=domain['name'] + "-" + datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
                CertificateBody=certificate,
                PrivateKey=key)
        else:
            res = iam.upload_server_certificate(
                Path='/',
                ServerCertificateName=domain['name'] + "-" + datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S"),
                CertificateBody=certificate,
                PrivateKey=key,
                CertificateChain=chain_certificate)
    except ClientError as e:
        LOG.error("Failed to upload certificate for domain '{0}'".format(domain['name']))
        LOG.error("Exception: {0}".format(e))
        return False

    return res

def update_elb_server_certificate(conf, domain, server_certificate_arn):
    """
    Assign the new SSL certificate to the desired ELB
    """
    elb = boto3.client('elb', config=Config(signature_version='v4', region_name=domain['elb_region']))

    timeout = 60
    while timeout > -1:
        try:
            res = elb.set_load_balancer_listener_ssl_certificate(
                LoadBalancerName=domain['elb'],
                LoadBalancerPort=domain['elb_port'],
                SSLCertificateId=server_certificate_arn)
            break
        except ClientError as e:
            if e.response['Error']['Code']  == 'CertificateNotFound':
                # occasionally server certificate may be reported as not found, even in the same region.
                # let's give a chance to iam to be aware of our changes especially when  an ELB is in a
                # different region
                sleep(1)
                timeout = timeout - 1
                continue

            LOG.error("Failed to set server certificate '{0}' on ELB '{0}:{1}' in region '{2}'".format(server_certificate_arn, domain['elb'], domain['elb_port'], domain['elb_region']))
            LOG.error("Exception: {0}".format(e))
            return False

    if timeout < 0:
        LOG.error("Could not set server certificate '{0}' within 60 seconds on ELB '{1}:{2}' in region '{3}'.".format(server_certificate_arn, domain['elb'], domain['elb_port'], domain['elb_region']))
        return False

    LOG.debug("Set server certificate '{0}' on ELB '{1}:{2}' in region '{3}' in {4} seconds.".format(
        server_certificate_arn,
        domain['elb'],
        domain['elb_port'],
        domain['elb_region'],
        60-timeout))

    return True

def answer_dns_challenge(conf, client, domain, challenge):
    """
    Compute the required answer and set it in the DNS record
    for the domain.
    """
    authorization = "{}.{}".format(
        base64.urlsafe_b64encode(challenge.get("token")).decode("ascii").replace("=", ""),
        base64.urlsafe_b64encode(client.key.thumbprint()).decode("ascii").replace("=", "")
        )

    dns_response = base64.urlsafe_b64encode(hashlib.sha256(authorization.encode()).digest()).decode("ascii").replace("=", "")

    # Let's update the DNS on our R53 account
    zone_id = get_route53_zone_id(conf, domain['r53_zone'])
    if zone_id == None:
        LOG.error("Cannot determine zone id for zone '{0}'".format(domain['r53_zone']))
        return None

    LOG.info("Domain '{0}' has '{1}' for Id".format(domain['r53_zone'], zone_id))

    zone_id = get_route53_zone_id(conf, domain['r53_zone'])
    if zone_id == None:
        LOG.error("Cannot find R53 zone {}, are you controling it ?".format(domain['r53_zone']))
        return None

    acme_domain = "_acme-challenge.{}".format(domain['name'])

    res = reset_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain)
    if res == None:
        LOG.error("An error occured while trying to remove a previous resource record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = create_route53_letsencrypt_record(conf, zone_id, domain['name'], acme_domain, 'TXT', '"' + dns_response + '"')
    if add_status == None:
        LOG.error("An error occured while creating the dns record. Skipping domain {0}".format(domain['name']))
        return None

    add_status = wait_letsencrypt_record_insync(conf, add_status)
    if add_status == None:
        LOG.error("Cannot determine if the dns record has been correctly created. Skipping domain {0}".format(domain['name']))
        return None

    if add_status == False:
        LOG.error("We updated R53 but the servers didn't sync within 60 seconds. Skipping domain {0}".format(domain['name']))
        return None

    if add_status is not True:
        LOG.error("An unexpected result code has been returned. Please report this bug. Skipping domain {0}".format(domain['name']))
        LOG.error("add_status={0}".format(add_status))
        return None

    ## Now, let's tell the ACME server that we are ready
    challenge_response = challenges.DNS01Response(key_authorization=authorization)
    challenge_resource = client.answer_challenge(challenge, challenge_response)

    if challenge_resource.body.error != None:
        return False

    return True

def create_and_save_key(conf, s3_key, kms_key='AES256'):
    """
    Generate a RSA 4096 key for general purpose (account or CSR)
    """
    LOG.info("Generating new RSA key")
    key = RSA.generate(4096).exportKey("PEM")
    save_to_s3(conf, s3_key, key, True, kms_key)
    return key

def save_to_s3(conf, s3_key, content, encrypt=False, kms_key='AES256'):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    LOG.debug("Saving object '{0}' to in 's3://{1}'".format(s3_key, conf['s3_bucket']))
    s3 = conf['s3_client']
    try:
        if encrypt == True:
            if  kms_key != 'AES256':
                s3.put_object(Bucket=conf['s3_bucket'],
                        Key=s3_key,
                        Body=content,
                        ACL='private',
                        ServerSideEncryption='aws:kms',
                        SSEKMSKeyId=kms_key)
            else:
                s3.put_object(Bucket=conf['s3_bucket'],
                        Key=s3_key,
                        Body=content,
                        ACL='private',
                        ServerSideEncryption='AES256')
        else:
                s3.put_object(Bucket=conf['s3_bucket'],
                        Key=s3_key,
                        Body=content,
                        ACL='private')
    except ClientError as e:
        LOG.error("Failed to save '{0}' in bucket '{1}'".format(s3_key, conf['s3_bucket']))
        LOG.error("Error: {0}".format(e))
        return None

def load_private_key(conf, domain):
    key = None
    name = domain['name'] + ".key.pem"

    if 'reuse_key' in domain.keys() and domain['reuse_key'] == True:
        LOG.debug("Attempting to load private key from S3 for domain '{0}'".format(domain['name']))
        key = load_from_s3(conf, name)

    if key == None:
        key = create_and_save_key(conf, name, domain['kmsKeyArn'])

    return crypto.load_privatekey(crypto.FILETYPE_PEM, key)

def generate_certificate_signing_request(conf, domain):
    key = load_private_key(conf, domain)

    LOG.info("Creating Certificate Signing Request.")
    csr = crypto.X509Req()
    csr.get_subject().countryName = domain['countryName']
    csr.get_subject().CN = domain['name']
    csr.set_pubkey(key)
    csr.sign(key, "sha1")
    return (csr, key)

def request_certificate(conf, domain, client, auth_resource):
    (csr, key) = generate_certificate_signing_request(conf, domain)

    try:
        (certificate, ar) = client.poll_and_request_issuance(ComparableX509(csr), [auth_resource])
    except errors.PollError as e:
        LOG.error("Failed to get certificate issuance for '{0}'.".format(domain['name']))
        LOG.error("Error: {0}".format(e))
        return (False, False, False)

    chain = requests.get(certificate.cert_chain_uri)
    chain_certificate = None

    if chain.status_code == 200:
        chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)
        pem_chain_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii")
    else:
        LOG.error("Failed to retrieve chain certificate. Status was '{0}'.".format(chain.status_code))
        pem_chain_certificate = False

    pem_certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate.body.wrapped).decode("ascii")
    pem_private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("ascii")

    return (pem_chain_certificate, pem_certificate, pem_private_key)

def lambda_handler(event, context):
    if 'bucket' not in event:
        LOG.critical("No bucket name has been provided. Exiting.")
        exit(1)
    s3_bucket = event['bucket']

    if 'region' not in event.keys() and 'AWS_DEFAULT_REGION' not in os.environ.keys():
        LOG.critical("Unable to determine AWS region code. Exiting.")
        exit(1)
    else:
        if 'region' not in event.keys():
            LOG.warning("Using local environment to determine AWS region code.")
            s3_region = os.environ['AWS_DEFAULT_REGION']
            LOG.warning("Local region set to '{0}'.".format(s3_region))
        else:
            s3_region = event['region']

    if 'defaultkey' not in event:
        LOG.warning("No default KMS key provided, defaulting to 'AES256'.")
        kms_key = 'AES256'
    else:
        LOG.info("Using {0} as default KMS key.".format(event['defaultkey']))
        kms_key = event['defaultkey']

    if 'config' not in event:
        letslambda_config = 'letslambda.yml'
    else:
        letslambda_config = event['config']


    LOG.info("Retrieving configuration file from bucket '{0}' in region '{1}' ".format(s3_bucket, s3_region))
    s3_client = boto3.client('s3', config=Config(signature_version='s3v4', region_name=s3_region))

    conf = load_config(s3_client, s3_bucket, letslambda_config)
    if conf == None:
        LOG.critical("Cannot load letslambda configuration. Exiting.")
        exit(1)

    conf['region'] = os.environ['AWS_DEFAULT_REGION']
    conf['s3_client'] = s3_client
    conf['s3_bucket'] = s3_bucket
    conf['letslambda_config'] = letslambda_config
    conf['kms_key'] = kms_key

    account_key = load_letsencrypt_account_key(conf)

    acme_client = client.Client(conf['directory'], account_key)
    for domain in conf['domains']:
        if 'r53_zone' not in domain.keys():
            LOG.error("Missing parameter 'r53_zone' for domain '{0}'. Skipping domain.".format(domain['name']))
            continue

        if 'kmsKeyArn' not in domain.keys():
            domain['kmsKeyArn'] = conf['kms_key']

        if 'reuse_key' not in domain.keys():
            domain['reuse_key'] = True

        if 'elb_port' not in domain.keys():
            domain['elb_port'] = 443

        if 'elb_region' not in domain.keys():
            domain['elb_region'] = conf['region']

        authorization_resource = get_authorization(acme_client, domain)
        challenge = get_dns_challenge(authorization_resource)
        res = answer_dns_challenge(conf, acme_client, domain, challenge)
        if res is not True:
            LOG.error("An error occurred while answering the DNS challenge. Skipping domain '{0}'.".format(domain['name']))
            continue

        (chain, certificate, key) = request_certificate(conf, domain, acme_client, authorization_resource)
        if key == False or certificate == False:
            LOG.error("An error occurred while requesting the signed certificate. Skipping domain '{0}'.".format(domain['name']))
            continue

        save_certificates_to_s3(conf, domain, chain, certificate)
        iam_cert = upload_to_iam(conf, domain, chain, certificate, key)
        if iam_cert is not False and iam_cert['ResponseMetadata']['HTTPStatusCode'] is 200 and 'elb' in domain.keys():
            update_elb_server_certificate(conf, domain, iam_cert['ServerCertificateMetadata']['Arn'])
        else:
            LOG.error("An error occurred while saving your server certificate in IAM. Skipping domain '{0}'.".format(domain['name']))
            continue
