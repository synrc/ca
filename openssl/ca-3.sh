#!/bin/bash

openssl ca -config ecc/synrc.cnf -passin pass:0 -gencrl -out ecc/eccroot.crl
