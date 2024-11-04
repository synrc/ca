#!/bin/sh

openssl cmp -cmd ir -server 127.0.0.1:1829 \
            -path . -srvcert ecc/caroot.pem -ref NewUser \
            -secret pass:0000 -certout x.pem -newkey ecc/maxim.key.enc -subject "/CN=maxim/O=SYNRC/ST=Kyiv/C=UA"
