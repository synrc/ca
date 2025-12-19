#!/bin/sh

export client=maxim39
openssl cmp -cmd p10cr -server localhost:8829 \
            -secret pass:0000 -ref cmptestp10cr -path . -srvcert synrc.pem \
            -certout ecc/$client.pem -csr ecc/$client.csr
