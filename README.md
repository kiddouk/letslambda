# LetsLambda #

A little python script that gets to renew your certificates from AWS Lambda via DNS challenge. It stores your keys in an S3 bucket. If the keys dont exists, it can generate them and re-use them later (useful for public key pinning).

All in all, it talks to letsencrypt, Route53 (for the dns challenge), IAM and ELB.

## Configuration ##
The configuration file is based on YAML. It should be easy to understand by reviewing the provided configuration. Nonetheless, here is a short explanation of each configuration directive

`directory`: the directory to use (useful when you need to switch between stagin and prod for letsencrypt)

`info`: the information to be used if the script has to register your user first

`domains`: a list of domain information.

 - `name`: this is used to configure endpoints, DNS, and CN for the certification
 - `countryName`: is used for countryName in the CSR
 - `reuse_key`: will try to reuse the same private key to generate the CSR. This is very useful if you ever want to use Public Key pinning in your mobile app and yet, want to renew your certificates every x months.

## Installation ##

This is the tricky part. This project relies on third party projects that requires some files to be compiled. Since AWS Lambda runs on Amazon Linux 64 bit, it is important that you have such instance running to prepare your Lambda function.

    $> yum install libcffi-devel libyaml-devel gcc openssl-devel git
    $> virtualenv .env
    $> source .env/bin/activate
    $> pip install -r requirements.txt
    $> mv .env/lib/python2.7/site-packages/* .
    $> mv .env/lib64/python2.7/site-packages/* .
    $> mv .env/src/acme/acme/acme* .
    $> rm -rf .env
    $> zip -r letslambda.zip .

If you're development environment is running on Debian Linux, you need the following commands:

    $> apt-get install -V python-virtualenv python-pip libssl-dev python-dev libffi-dev
    $> virtualenv .env
    $> source .env/bin/activate
    $> pip install -r requirements.txt
    $> mv .env/lib/python2.7/site-packages/* .
    $> mv .env/lib64/python2.7/site-packages/* .
    $> mv .env/src/acme/acme/acme* .
    $> rm -rf .env
    $> zip -r letslambda.zip .

Once this is done, all you have to do is to upload your lamnbda function to an S3 bucket.

    $> aws s3 cp letslambda.zip s3://bucket/

And finally, let cloudforamtion due the heavy job.

    $> aws cloudformation create-stack --stack-name letslambda --template-body  file://letslambda.json --parameters ParameterKey=Bucket,ParameterValue=bucket --capabilities CAPABILITY_IAM


This should be all.
