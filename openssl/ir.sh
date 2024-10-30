#!/bin/sh

openssl cmp -cmd ir -server 127.0.0.1:1829 \
            -path . -srvcert ca.pem -ref NewUser \
            -secret pass:0000 -certout x.pem -newkey maxim.key.enc -subject "/CN=maxim/O=SYNRC/ST=Kyiv/C=UA"
