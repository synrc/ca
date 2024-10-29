#!/bin/bash

export CLIENT=client
openssl ec -in cert/ecc/$CLIENT.key.enc -out cert/ecc/$CLIENT.key -passin pass:0
