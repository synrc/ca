#!/bin/bash

openssl ca -config cert/ecc/synrc.cnf -passin pass:0 -gencrl -out cert/ecc/eccroot.crl
