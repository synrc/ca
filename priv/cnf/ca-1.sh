#!/bin/bash

openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -passout pass:0 -out cert/ecc/caroot.key
