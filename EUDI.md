EU Digital Identity
===================

SYNRC CA server supports decentralized EUDI issuing architecture.

### Architecture

EUDI is decetralized PKIX with ABAC level control over attributes.

* eIDAS Node -- State Certificate Authority
* EUID Wallet -- iOS/Android Application
* EUDI Provider -- OpenID for Verifiable Credentials (OpenID4VC)
* Personal Identification Data Provider (PP) -- Diia State Enterprise (PID) mDOC
* Attestation Providers (AT) -- Qualified and Non-Qualified Electronic Attestation (QEAA) of Attributes Schema Providers
* Qualifiied Electronic Signature Provider (QP) -- Qualified Certificates (QC)
* EUDI Verifier -- Verifiable Presentations

### Holder, Issuer, Verifier

In an OpenID4VC ecosystem, the Verifier and the Issuer are connected indirectly
through the credential lifecycle, with interactions primarily mediated by the Holder. 
This architecture ensures trust without requiring a direct, continuous relationship
between the Verifier and the Issuer, adhering to privacy and decentralization principles.
The Verifier does not directly contact the Issuer during typical operations unless a status check is required.
The Holder acts as the intermediary, ensuring their privacy and control over the data being shared.

EUDI Wallet acts as Holder, QEAA, EAA, PIP (TSPs) act as EUDI Providers or Issuers. EUDI Verifier perform
status verification of credentials and acts as Verifier.

### PKIX vs OpenID4VC

EUDI model has a similarity with PKIX.
The same way person use a signed attribute set (a X.509 certificate from CSR attributes)
for authentication and authorization in PKI, the OpenID4VC provider (PIP) envelops
set of attributes (digital presentation of claims) and
issue and Electronic Documents in mDOC format for EUDI Wallet.

However, unlike PKIX with its centralized model,
EUDI provide distributed model without single root CA,
where all parties bounded cryptographycally. Also, EUDI has more subtle
and rigorous control over attributes (claims) like in ABAC model.

CRLs and OCSP can create privacy concerns since they involve
querying a CA, potentially exposing the user's activity.
OpenID4VC mitigates this by enabling the Holder to mediate
the process, and some implementations avoid real-time statu
checks entirely by including cryptographic proofs within the
credential itself.

