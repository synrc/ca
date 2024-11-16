EU Digital Identity
===================

CA Server supports EUDI architecture.

EUDI Architecture
-----------------

* eIDAS Node -- State Certificate Authority
* EUID Wallet -- iOS/Android Application
* EUDI Provider -- OpenID for Verifiable Credentials (OpenID4VC)
  Personal Identification Data Provider (PP) -- Diia State Enterprise (PID) mDOC
  Attestation Providers (AT) -- Qualified and Non-Qualified Electronic Attestation (QEAA) of Attributes Schema Providers
* Qualifiied Electronic Signature Provider (QP) -- Qualified Certificates (QC)
* EUDI Verifier -- Verifiable Presentations

ISO/IEC 18013-5-compliant EUDI Wallets:

```asn1
id-eudi OBJECT IDENTIFIER ::= {european-commission 2}
id-eudi-iso OBJECT IDENTIFIER ::= {id-eudi 0}
id-eudi-iso-pid OBJECT IDENTIFIER ::= {id-eudi-iso 0}
id-eudi-iso-pid-kp OBJECT IDENTIFIER ::= {id- eudi-iso-pid 1}
id-eudi-iso-pid-kp-DS OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp 2}
id-eudi-iso-pid-kp-ReaderAuth OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp 6}
id-eudi-iso-pid-kp-IACALink OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp 4}
id-eudi-iso-pid-kp-IACA OBJECT IDENTIFIER ::= {id-eudi-iso-pid-kp 7}
```

Conformance
-----------

6 Use Cases of EUDI https://www.digital-identity-wallet.eu/

1. PID issuance
2. PID attribution
3. (Q)EAA issuance
4. mDL attribution
5. HIID attribution
6. IBAN attribution
7. eSIM attribution
   
