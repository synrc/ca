#!/bin/bash

export CLIENT=maxim
openssl ca -config ecc/synrc.cnf -passin pass:0 \
           -extensions usr_cert -batch -days 365 \
           -in ecc/$CLIENT.csr -out ecc/$CLIENT.pem \
           -cert ecc/caroot.pem -keyfile ecc/caroot.key

openssl pkcs12 -export \
               -inkey ecc/$CLIENT.key -in ecc/$CLIENT.pem \
               -out ecc/$CLIENT.p12
