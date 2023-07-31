#!/bin/sh

export client=maxim

#            -secret pass:0000 

openssl cmp -cmd p10cr -server localhost:1829 \
            -path . -srvcert ca.pem -ref cmptestp10cr -unprotected_requests \
            -certout $client.pem -csr $client.csr
