#!/bin/sh

export client=client
openssl dgst -sha256 -verify $client.pub -signature mix.sig mix.exs
