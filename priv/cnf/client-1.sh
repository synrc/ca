#!/bin/bash

export CLIENT=client
openssl req -config cert/ecc/synrc.cnf -batch \
            -passin pass:0 -passout pass:0 \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout cert/ecc/$CLIENT.key \
            -out cert/ecc/$CLIENT.csr \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN="$CLIENT
