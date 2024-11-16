EU Digital Identity
===================

CA Server supports EUDI architecture.

EUDI Architecture
-----------------

* EUID Wallet (iOS/Android) Application
* EUDI Wallet Provider
* Personal Identification Data (PID) Provider -- Diia State Enterprise
* Qualified Electronica Attestation (QEAA) Provider -- Government agencies and registries
* Non-Qualified Electronica Attestation (EAA) Provider -- Commertical affiliated companies

ISO/IEC 18013-5-compliant EUDI Wallets:

```asn1
id-eudi OBJECT IDENTIFIER ::= {european-commission 2}
id-eudi-iso OBJECT IDENTIFIER ::= {id-eudi 0}
id-eudi-iso-pid OBJECT IDENTIFIER ::= {id-eudi-iso 0}
id-eudi-iso-pid-kp OBJECT IDENTIFIER ::= {id- eudi-iso-pid 1}
id-eudi-iso-pid-kp-DS OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp2}
id-eudi-iso-pid-kp-ReaderAuth OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp 6}
```

Conformance
-----------

1. PID issuance
2. PID attribution
3. (Q)EAA issuance
4. mDL attribution
5. HIID attribution
6. IBAN attribution
7. eSIM attribution
   
