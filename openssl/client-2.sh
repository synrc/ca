#!/bin/bash

export CLIENT=maxim
openssl ec -in ecc/$CLIENT.key.enc -out ecc/$CLIENT.key -passin pass:0
