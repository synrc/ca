# SYNRC 🛡️ CA

[![Actions Status](https://github.com/synrc/ca/workflows/mix/badge.svg)](https://github.com/synrc/ca/actions)
[![Hex pm](https://img.shields.io/hexpm/v/ca.svg?style=flat)](https://hex.pm/packages/ca)

![ca-shaders](https://ca.n2o.dev/priv/design/ca-shaders.png)

## Features

* PKI entities: `CA`, `RA`, `SERVER`, `CLIENT`, `HUMAN`, `PROGRAM`
* Key purposes: `TLS`, `ECDSA`, `AES`, `SSH`, `SCVP`, `IPSEC`, `CMC`, `SIP`, `CAP`, `EAP`, `BGP`, `OCSP`
* EUID documents: `TAXID`, `PID`, `IBAN`, `HIID`, `LOYAL`
* Curve profiles: `secp256k1`, `secp384r1`, `secp521r1`
* DH Schemes: `RSA`, `GF(p)`, `GF(2^m)`
* RFC: CMS, PKCS-10, CMP, ESP, OCSP, TSP
* Ports: CMP (TCP 8829), EST (HTTP 8047), CMC (TCP 5318)
* Size: 2000 LOC
* ECDSA: Pure Elixir
* CMS: Pure Elixir
* Support for DSTU-4145 Polynomials over Binary Galois Fields GF(2^m) envelops

## Documentation

* Hex Docs https://hexdocs.pm/ca/api-reference.html

## Online Instances

* https://ca.n2o.dev/
* https://erp.uno/ca/

## How to use?

On Windows:

```
c:\Progra~1\OpenSSL-Win64\bin\openssl.exe ecparam -name secp384r1 -genkey | Out-File -Encoding utf8 "1.txt"
c:\Progra~1\OpenSSL-Win64\bin\openssl.exe req -passout pass:0 -new -key 1.txt -keyout dima.key.enc -out dima.csr -subj "/C=FI/ST=Helsinki/O=AR.VO/CN=A13" 2>null
c:\Progra~1\OpenSSL-Win64/bin/openssl.exe cmp -cmd p10cr -server http://ca.synrc.com:8829/ -secret pass:0000 -ref cmptestp10cr -csr dima.csr -certout dima.pem
```

On UNIX:

```
$ openssl req -passout pass:0 -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout dima.key.enc -out dima.csr -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=dima"
$ openssl cmp -cmd p10cr -server "ca.synrc.com":8829 -secret pass:0000 -ref cmptestp10cr -certout dima.pem -csr dima.csr
```

## Authors

* Максим Сохацький
* Євгеній Гадібіров
* Георгій Мельник-Веттштайн
