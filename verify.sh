#!/bin/sh

export client=m2
openssl dgst -sha256 -verify $client.pub -signature mix.sig mix.exs
