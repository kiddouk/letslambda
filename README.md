# LetsLambda #

A python script that gets to renew your SSL certificates from AWS Lambda via DNS challenge using [Let's Encrypt](https://letsencrypt.org/) services. It stores your keys and certificates in a S3 bucket. If the keys don't exists, it generates them and re-uses them later (useful for [public key pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)).

All in all, the script talks to [Let's Encrypt](https://letsencrypt.org/) and Amazon [Route53](https://aws.amazon.com/route53/) (for the DNS challenge), Amazon [S3](https://aws.amazon.com/s3/) and Amazon [IAM](https://aws.amazon.com/iam/) (to store your certificates) and Amazon [Elastic Load Balancing](https://aws.amazon.com/elasticloadbalancing/). And optionally, Amazon [KMS](https://aws.amazon.com/kms/) can be used to encrypt your data in your S3 bucket.

## Configuration ##
The configuration file is based on YAML. It should be easy to understand by reviewing the provided configuration. Nonetheless, here is a short explanation of each configuration directive

`directory`: The Let's Encrypt directory endpoint to use to request the certificate issuance. This is useful when you need to switch between staging and production. Possible values are:

 - `https://acme-v01.api.letsencrypt.org/directory` for production
 - `https://acme-staging.api.letsencrypt.org/directory` for development and tests

`info`: The information to be used when the script is registering your account for the first time. You should provide a valid email or the registration may fail.

    info:
        - mailto:myemail@example.com

`domains`: a list of domain information.

 - `name`: The host name for which you want your certificate to be issued for.
 - `r53_zone`: the Route53 hosted zone name which contains the DNS entry for `name`.
 - `countryName`: This parameter is used for `countryName` in the [Certificate Signing Request](https://en.wikipedia.org/wiki/Certificate_signing_request) (CSR).
 - `elb`: Name of your Elastic Load Balancer.
 - `elb_port`: ELB listening port. If left unspecified, the default is 443 (HTTPS).
 - `elb_region`: the region is which your ELB has been deployed in. Default is the Lambda local region.
 - `kmsKeyArn`: Your KMS key arn to encrypt the Let's Encrypt account key and your certificate private keys. You may also use `AES256` for AWS managed at rest encryption. Default is `AES256`.
 - `reuse_key`: The Lambda function will try to reuse the same private key to generate the new CSR. This is useful if you ever want to use Public Key Pinning (Mobile App development) and yet want to renew your certificates every X months

## Installation ##

This project relies on third party projects that requires some files to be compiled. Since AWS Lambda runs on Amazon Linux 64 bit ([ref](http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html)), it's important that you have such instance running to prepare your Lambda function 8and not a custom debian/ubuntu server as you may find some libraries incompatibilities).

    $> yum install libcffi-devel libffi-devel libyaml-devel gcc openssl-devel git
    $> virtualenv .env
    $> source .env/bin/activate
    $> pip install -r requirements.txt
    $> mv .env/lib/python2.7/site-packages/* .
    $> mv .env/lib64/python2.7/site-packages/* .
    $> mv .env/src/acme/acme/acme* .
    $> rm -rf .env
    $> zip -r letslambda.zip .

Once this is done, all you have to do is to upload your lambda function to a S3 bucket.

    $> aws s3 cp letslambda.zip s3://bucket/
Alternatively, you may use the Amazon Management Console to upload your package from the comfort of your web browser.

And finally, let Amazon CloudFormation do the heavy job of deploying your Lambda function.

    $> aws cloudformation create-stack --stack-name letslambda --template-body  file://letslambda.json --parameters ParameterKey=Bucket,ParameterValue=bucket --capabilities CAPABILITY_IAM
As a possible alternative, you may use the CloudFormation Management Console to deploy your Lambda function. Though, you should ensure that you deploy the IAM resources included in the template.

## Role and Managed Policies ##
As part of the deployment process, the CloudFormation template will create 4 IAM managed policies and one Lambda execution role. Each managed policy has been crafted so you can access your resources securely. The Lambda execution role defines the privilege level for the Lambda function.

 - `LetsLambdaManagedPolicy` This policy is core to the Lambda function and how it interacts with CloudWatch logs, Amazon IAM, Amazon Elastic Load Balancing and Route53.
 - `LetsLambdaKmsKeyManagedPolicy`Through this policy, the Lambda function can encrypt and read encrypted private keys.
 - `LetsLambdaS3WriteManagedPolicy`Allow the Lambda function to write into the user defined S3 bucket.
 - `LetsLambdaS3ReadManagedPolicy` This policy is used to access any objects in the S3 bucket. Encrypted objects such as private keys will remain inaccessible until `LetsLambdaKmsKeyManagedPolicy`is used in conjunction with this policy.

### Accessing your Private keys ###
Having access to private keys is sensitive by definition. You should ensure that your private keys do not leak outside in any way. 

To retrieve more easily your private keys from an EC2 instance, you should create/update an EC2 role and add both `LetsLambdaKmsKeyManagedPolicy` and `LetsLambdaS3ReadManagedPolicy`. This will allow your the EC2 instances running under the corresponding role/managed policies to access the private keys without any hard coded credentials.

## Credits ##
 - [Sébastien Requiem](https://github.com/kiddouk/)
 - [Aurélien Requiem](https://github.com/aureq/)

### Contributors ###
- [Peter Mounce](https://github.com/petemounce)

