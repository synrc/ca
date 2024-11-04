#!/bin/bash

export SERVER=server
openssl ca -config ecc/synrc.cnf -days 730 -batch \
           -in ecc/$SERVER.csr -out ecc/$SERVER.pem \
           -keyfile ecc/caroot.key -cert ecc/caroot.pem \
           -passin pass:0 -extensions server_cert
