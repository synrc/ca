#!/bin/bash

export SERVER=server
openssl ca -config cert/ecc/synrc.cnf -days 730 -batch \
           -in cert/ecc/$SERVER.csr -out cert/ecc/$SERVER.pem \
           -keyfile cert/ecc/caroot.key -cert cert/ecc/caroot.pem \
           -passin pass:0 -extensions server_cert \
