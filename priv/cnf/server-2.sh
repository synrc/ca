#!/bin/bash

export SERVER=server
openssl ec -in cert/ecc/$SERVER.key.enc -out cert/ecc/$SERVER.key -passin pass:0 -passout pass:0
