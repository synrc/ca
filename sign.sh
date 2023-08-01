#!/bin/sh

export client=m2
openssl dgst -sha256 -sign $client.key mix.exs > mix.sig
