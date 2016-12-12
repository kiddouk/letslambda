#!/bin/sh

sudo yum install -y libcffi-devel libyaml-devel gcc openssl-devel git zip python27-virtualenv
virtualenv .env
. .env/bin/activate
pip install -r requirements.txt
mv .env/lib/python2.7/site-packages/* .
mv .env/lib64/python2.7/site-packages/* .
mv .env/src/acme/acme/acme* .
rm -rf .env
zip -r letslambda.zip .
