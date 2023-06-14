#!/bin/bash

export SERVER=server
openssl req -config cert/ecc/synrc.cnf \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout cert/ecc/$SERVER.key.enc \
            -out cert/ecc/$SERVER.csr -passout pass:0 \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN="$SERVER
