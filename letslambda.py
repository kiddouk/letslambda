# -*- coding: utf-8 -*-

import yaml
from Crypto.PublicKey import RSA
from boto import s3
from boto import iam
from boto import route53
from boto.s3.connection import OrdinaryCallingFormat
from boto.s3.key import Key
from boto.exception import S3ResponseError
import logging
from acme import client
from acme import messages
from acme import challenges
import io
import requests
import base64
import hashlib
from time import sleep
from OpenSSL import crypto
from datetime import datetime
from boto.ec2 import elb
from acme.jose.util import ComparableX509

LOG = logging.getLogger("letslambda")
LOG.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# add formatter to ch
handler.setFormatter(formatter)
# add ch to logger
LOG.addHandler(handler)

def load_config(bucket):
    conf = bucket.get_key("letslambda.yml")
    confString = conf.read()
    conf = yaml.load(confString)
    return conf

def loadAccountKey(bucket):
    """
    Try to load the RSA account key from S3. If it doesn't
    succeed, it will create a new account key and try a registration
    with your provided information
    """
    LOG.info("Loading account key from s3")
    key = bucket.get_key("account.key.rsa")
    newAccountNeeded = False;
    if key == None:
        pem = createAndSaveKey(bucket, "account.key.rsa")
        newAccountNeeded = True
    else:
        pem = key.read()

    key = client.jose.JWKRSA.load(pem)
    if newAccountNeeded:
        registerNewAccount(conf, key)

    return key

def loadCSRKey(bucket, domain):
    LOG.info("Loading CSR key from S3")
    key = None
    if 'reuse_key' in domain.keys() and domain['reuse_key'] == True:
        LOG.info("Attempting to reuse old key for domain")
        name = domain['name'] + ".key.rsa"
        key = bucket.get_key(name)

    if key == None:
        pem = createAndSaveKey(bucket, name)
    else:
        pem = key.read()

    return crypto.load_privatekey(crypto.FILETYPE_PEM, pem)

def registerNewAccount(conf, key):
    """
    Attempt to create a new account on the ACME server
    with the key. No problem if it fails because this
    kye is already used.
    """
    LOG.info("Registering with ACME server with the new key")
    newReg = messages.NewRegistration(contact=tuple(conf['info']), key=key.public_key())
    acme_client = client.Client(conf['directory'], key)
    registration_resource = acme_client.register(newReg)
    LOG.info("Agreeing on the TOS on your behalf")
    acme_client.agree_to_tos(registration_resource)

def createAndSaveKey(bucket, name):
    """
    Generate an RSA 4096 key for general purpose (account or CSR)
    """
    LOG.info("Key not found! Generating new RSA key")
    key = RSA.generate(4096);
    saveToS3(bucket, key, name)
    return key.exportKey("PEM")

def saveToS3(bucket, rsakey, name):
    """
    Save the rsa key in PEM format to s3 .. for later use
    """
    LOG.info("Storing newly generated key")
    s3key = Key(bucket=bucket, name=name)
    fp = io.BytesIO(rsakey.exportKey("PEM"));
    s3key.set_contents_from_file(fp)

def get_authorization(client, domain):
    authorization_resource = client.request_domain_challenges(domain['name'])
    return authorization_resource;

def get_dns_challenge(authorization_resource):
    """
    Ask the ACME server to give us a list of challenges.
    Later, we will pick only the DNS one.
    """
    # Now let's look for a DNS challenge
    dns_challenges = filter(lambda x: isinstance(x.chall, challenges.DNS01), authorization_resource.body.challenges)
    return list(dns_challenges)[0]

def answer_dns_challenge(client, domain, challenge):
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
    top_level = ".".join(domain['name'].split(".")[-2:])
    r53 = route53.connect_to_region("eu-west-1")
    zone = r53.get_zone(top_level)
    if zone == None:
        LOG.error("Cannot find R53 zone {}, are you controling it ?".format(top_level))
        exit(1)

    acme_domain = "_acme-challenge.{}".format(domain['name'])
    record = zone.find_records(name=acme_domain, type="TXT")
    if record:
        delete_status = zone.delete_record(record)

    add_status = zone.add_record("TXT", acme_domain, '"' + dns_response + '"')
    dns_updated = wait_until_sync(add_status)

    if dns_updated == False:
        LOG.error("We updated R53 but the servers didn't sync within 10 seconds. Bailing out.")
        exit(1)

    ## Now, let's tell the ACME server that we are ready
    challenge_response = challenges.DNS01Response(key_authorization=authorization)
    challenge_resource = client.answer_challenge(challenge, challenge_response)

    # We'd better poll to get the answer of this.
    LOG.debug(challenge_resource)

def generateCSR(bucket, conf):
    if 'reuse_key' in conf:
        key = loadCSRKey(bucket, conf)
    else:
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

    csr = crypto.X509Req()
    csr.get_subject().countryName = conf['countryName']
    csr.get_subject().CN = conf['name']
    csr.set_pubkey(key)
    csr.sign(key, "sha1")
    LOG.debug(base64.urlsafe_b64encode(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, csr)))
    return (csr, key)

def requestCertificate(client, bucket, conf, auth_resource):
    (csr, key) = generateCSR(bucket, conf)
    # Gently wait for authorization to be valid
    # wait_until_valid(auth_resource)

    (certificate, ar) = client.poll_and_request_issuance(ComparableX509(csr), [auth_resource])
    return (certificate, key)

def wait_until_valid(auth):
    timeout = 30
    valid = False
    while valid and timeout > -1:
        status = requests.get(auth.uri)
        if status['status'] == "valid":
            valid = True

    return valid

def wait_until_sync(status):
    LOG.info("Waiting for DNS to synchronize with new TXT value")
    timeout = 30;
    while status.status != "INSYNC" and timeout > -1:
        sleep(1)
        timeout = timeout - 1;
        status.update()

    if timeout == -1:
        return False

    return True

def createIAMCertificate(domain, certificate, key):
    """
    Create a new IAM certificate from ACME and private key.
    It also fetched the chain certificate from ACME if provided
    """
    # First we fetch the chain certificate
    chain = requests.get(certificate.cert_chain_uri)
    chain_certificate = None
    if chain.status_code == 200:
        chain_certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, chain.content)

    iam_connection = iam.connect_to_region("eu-west-1")
    res = iam_connection.upload_server_cert(
        domain['name'] + "-" + datetime.utcnow().strftime("%Y-%m-%dT%H-%M"),
        crypto.dump_certificate(crypto.FILETYPE_PEM, certificate.body.wrapped).decode("ascii"),
        crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("ascii"),
        crypto.dump_certificate(crypto.FILETYPE_PEM, chain_certificate).decode("ascii"),
        "/")
    sleep(10)

    return res

def updateELB(conf, iam_certificate):
    LOG.info("Updating ELB with new certificate")
    LOG.info(iam_certificate)
    elb_connection = elb.connect_to_region("eu-west-1")
    response = elb_connection.set_lb_listener_SSL_certificate(conf['elb'], 443, iam_certificate['upload_server_certificate_response']['upload_server_certificate_result']['server_certificate_metadata']['arn'])
    return response

def lambda_handler(event, context):
    LOG.info(event);
    bucket = event['bucket']

    LOG.info("Retrieving configuration file from bucket : {}".format(bucket))
    connection = s3.connect_to_region("eu-west-1", calling_format=OrdinaryCallingFormat())
    try:
        bucket = connection.get_bucket(bucket);
    except S3ResponseError as e:
        print(e)
        LOG.error("Cannot fetch bucket : {}".format(bucket))
        exit(1)

    conf = load_config(bucket)
    key = loadAccountKey(bucket)
    domain = conf['domains'][0]

    acme_client = client.Client(conf['directory'], key)
    authorization_resource = get_authorization(acme_client, domain)
    challenge = get_dns_challenge(authorization_resource)
    answer_dns_challenge(acme_client, domain, challenge)
    (certificate, key) = requestCertificate(acme_client, bucket, domain, authorization_resource)
    iam_cert = createIAMCertificate(domain, certificate, key)
    updateELB(domain, iam_cert)
