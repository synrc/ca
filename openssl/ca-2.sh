#!/bin/bash

openssl req -config ecc/synrc.cnf -days 3650 \
            -new -x509 -passin pass:0 \
            -key ecc/caroot.key -out ecc/caroot.pem \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=CA"
