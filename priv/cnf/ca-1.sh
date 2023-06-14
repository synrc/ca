#!/bin/bash

openssl ecparam -genkey -name secp384r1 -out cert/ecc/ca.key
openssl ec -aes256 -passout pass:0 -in cert/ecc/ca.key -out cert/ecc/caroot.key
