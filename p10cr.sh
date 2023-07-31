#!/bin/sh

export client=maxim

openssl cmp -cmd p10cr -server localhost:1829 \
            -path . -srvcert ca.pem -ref cmptestp10cr \
            -secret pass:ThisIsClassified -certout $client.pem -csr $client.csr
