#!/bin/sh

export client=maxim
openssl cmp -cmd p10cr -server localhost:1829 -secret pass:0000 \
            -path . -srvcert ca.pem -ref cmptestp10cr \
            -certout $client.pem -csr $client.csr
