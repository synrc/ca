#!/bin/bash

export SERVER=server
openssl ec -in ecc/$SERVER.key.enc -out ecc/$SERVER.key -passin pass:0
