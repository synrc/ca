#!/bin/sh

export client=maxim
openssl x509 -pubkey -noout -in $client.pem > $client.pub
openssl dgst -sha256 -verify $client.pub -signature mix.sig mix.exs
