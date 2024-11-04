#!/bin/bash

openssl ecparam -genkey -name secp384r1 -out ecc/ca.key
openssl ec -aes256 -passout pass:0 -in ecc/ca.key -out ecc/caroot.key
