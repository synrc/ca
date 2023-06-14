#!/bin/bash

export SERVER=server
openssl req -config cert/ecc/synrc.cnf \
            -passin pass:0 -passout pass:0 \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout cert/ecc/$SERVER.key.enc \
            -out cert/ecc/$SERVER.csr \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN="$SERVER
