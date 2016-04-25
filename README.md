# LetsLambda #

A little python script that gets to renew your certificates from AWS Lambda via DNS challenge. It stores your keys in an S3 bucket. If the keys dont exists, it can generate them and re-use them later (useful for public key pinning).

All in all, it talks to letsencrypt, Route53 (for the dns challenge), IAM and ELB.

## Configuration ##
The configuration file is based on YAML. It should be easy to understand by reviewing the provided configuration. Nonetheless, here is a short explanation of each configuration directive

`directory`: the directory to use (useful when you need to switch between stagin and prod for letsencrypt)
`info`: the information to be used if the script has to register your user first
`domains`: a list of domain information.
 `name`: this is used to configure endpoints, DNS, and CN for the certification
 `countryName`: is used for countryName in the CSR
 `reuse_key`: will try to reuse the same private key to generate the CSR. This is very useful if you ever want to use Public Key pinning in your mobile app and yet, want to renew your certificates every x months.

## Installation ##
