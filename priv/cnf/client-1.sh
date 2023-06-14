#!/bin/bash

export CLIENT=client
openssl req -config cert/ecc/synrc.cnf -passout pass:0 \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout cert/ecc/$CLIENT.key.enc -out cert/ecc/$CLIENT.csr \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN="$CLIENT
