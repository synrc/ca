#!/bin/bash

export CLIENT=client
openssl ca -config cert/ecc/synrc.cnf -passin pass:0 \
           -extensions usr_cert -batch -days 365 \
           -in cert/ecc/$CLIENT.csr -out cert/ecc/$CLIENT.pem \
           -cert cert/ecc/caroot.pem -keyfile cert/ecc/caroot.key

openssl pkcs12 -export \
               -inkey cert/ecc/$CLIENT.key -in cert/ecc/$CLIENT.pem \
               -out cert/ecc/$CLIENT.p12
