#!/bin/sh

export client=client
openssl dgst -sha256 -sign $client.key mix.exs > mix.sig
