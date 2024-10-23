#!/bin/sh

export client=maxim
openssl dgst -sha256 -sign $client.key mix.exs > mix.sig
