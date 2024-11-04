#!/bin/sh

export client=maxim
openssl x509 -pubkey -noout -in ecc/$client.pem > ecc/$client.pub
openssl dgst -sha256 -verify ecc/$client.pub -signature mix.sig ../mix.exs
