#!/bin/sh

export client=maxim
openssl cmp -cmd p10cr -server localhost:1829 -secret pass:0000 \
            -path . -srvcert synrc.pem -ref cmptestp10cr \
            -certout ecc/$client.pem -csr ecc/$client.csr
