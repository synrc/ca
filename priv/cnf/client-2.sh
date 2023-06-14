#!/bin/bash

export CLIENT=client
openssl ca -config cert/ecc/synrc.cnf \
           -extensions usr_cert -batch -days 365 -passin pass:0 \
           -in cert/ecc/$CLIENT.csr -out cert/ecc/$CLIENT.pem \
           -cert cert/ecc/caroot.pem -keyfile cert/ecc/caroot.key
