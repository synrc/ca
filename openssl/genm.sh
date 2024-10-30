#!/bin/sh

openssl cmp -cmd genm -server 127.0.0.1:1829 \
            -recipient "/CN=CMPserver" -ref 1234 -secret pass:0000
