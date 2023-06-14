#!/bin/bash

openssl req -config cert/ecc/synrc.cnf -days 3650 \
            -new -x509 -passin pass:0 \
            -key cert/ecc/caroot.key -out cert/ecc/caroot.pem \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=CA"
