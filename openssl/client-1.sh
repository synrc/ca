#!/bin/bash

export CLIENT=maxim35
openssl req -passout pass:0 \
            -new -newkey ec:<(openssl ecparam -name secp384r1) \
            -keyout ecc/$CLIENT.key.enc -out ecc/$CLIENT.csr \
            -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=$CLIENT"
