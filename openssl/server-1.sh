#!/bin/bash

export SERVER=server
openssl req -config ecc/synrc.cnf \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout ecc/$SERVER.key.enc \
            -out ecc/$SERVER.csr -passout pass:0 \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=$SERVER"
