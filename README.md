# SYNRC 🛡️ CA

[![Actions Status](https://github.com/synrc/ca/workflows/mix/badge.svg)](https://github.com/synrc/ca/actions)
[![Hex pm](http://img.shields.io/hexpm/v/ca.svg?style=flat)](https://hex.pm/packages/ca)

![ca-shaders](https://authority.erp.uno/priv/design/ca-shaders.png)

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

* https://authority.erp.uno

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

## Publications

* <a href="https://tonpa.guru/stream/2010/2010-10-18 LDAP.htm">2010-10-18 LDAP</a><br>
* <a href="https://tonpa.guru/stream/2020/2020-02-03 Кваліфікований Електронний Підпис.htm">2020-02-03 Кваліфікований Електронний Підпис</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-06-22 Месенжер.htm">2023-06-22 CMS Месенжер (Пітч)</a><br>
* <a href="https://chat.erp.uno">2023-06-30 ЧАТ X.509 (Домашня сторінка)</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-07-05 CMS SMIME.htm">2023-07-05 CMS S/MIME</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-07-16 CMS Compliance.htm">2023-07-16 CMS Compliance</a>
* <a href="https://tonpa.guru/stream/2023/2023-07-20 LDAP Compliance.htm">2023-07-20 LDAP Compliance</a><br>
* <a href="https://ldap.erp.uno">2023-07-25 LDAP 13.7.24 (Домашня сторінка)</a><br>
* <a href="https://authority.erp.uno">2023-07-30 CA X.509 (Домашня сторінка)</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-07-21 CMP CMC EST.htm">2023-07-21 CMP/CMC/EST</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-07-27 MLS.htm">2023-07-21 MLS ROOM CHAT</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-08-05 CA CURVE.htm">2023-08-05 CA CURVE</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-08-07 CHAT ASN.1.htm">2023-08-07 CHAT ASN.1</a><br>
* <a href="https://tonpa.guru/stream/2023/2023-08-08 ASN.1 Компілятор.htm">2023-08-08 ASN.1 Компілятор</a><br>
* <a href="https://tonpa.guru/stream/2024/2024-10-29 EST.htm">2024-10-29 EST сервер 7030</a><br>

## Credits

Максим Сохацький
