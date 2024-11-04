#!/bin/sh

export client=maxim
openssl dgst -sha256 -sign ecc/$client.key ../mix.exs > mix.sig
