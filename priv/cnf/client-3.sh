#!/bin/bash

export CLIENT=client
openssl pkcs12 -export \
         -passin pass:0 -passout pass:0 \
         -inkey cert/ecc/$CLIENT.key \
         -in cert/ecc/$CLIENT.pem \
         -out cert/ecc/$CLIENT.p12
