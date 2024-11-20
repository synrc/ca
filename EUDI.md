EU Digital Identity
===================

SYNRC CA server supports EUDI.

### Architecture

EUDI is decentralized PKIX with ABAC level control over attributes that is using JSON as encoding and HTTP as transport.

* eIDAS Node (CA) -- State Certificate Authority (SAML/HTTP, PKIX, JSON/HTTP)
* EUDI Verification Service Provider (VSP), Verifier -- Verifiable Presentations (VP, mDOC)
* EUID Wallet, Holder -- iOS/Android Application (PKIX, mDOC, OpenID4VC)
* EUDI Trusted Service Provider (TSP), Issuer -- OpenID for Verifiable Credentials (OpenID4VC, mDOC, SAML)
* Personal Identification Data (PID) Provider -- Diia State Enterprise (MSO mDOC)
* Qualified and Non-Qualified Electronic Attestation of Attributes (QEAA) Schema Providers (MSO mDOC)
* Qualifiied Electronic Signature Provider (QSP) -- Qualified Certificates (QC)

### Holder, Issuer, Verifier

In an OpenID4VC ecosystem, the Verifier and the Issuer are connected indirectly
through the credential lifecycle, with interactions primarily mediated by the Holder. 
This architecture ensures trust without requiring a direct, continuous relationship
between the Verifier and the Issuer, adhering to privacy and decentralizition principles.
The Verifier does not contact the Issuer directly during routine operations unless a
status check is necessary. The Holder acts as an intermediary, maintaining privacy
and control over shared data.

EUDI Wallet acts as Holder, QEAA, EAA, PIP (TSPs) act as EUDI Providers or Issuers.
EUDI Verifier perform status verification of credentials and acts as presentations Verifier.

### PKIX vs EUDI

EUDI model has a similarity with PKIX.
The same way person use a signed attribute set (a X.509 certificate from CSR attributes)
for authentication and authorization in PKI, the OpenID4VC provider (PIP) envelops
set of attributes (digital presentation of claims) and
issue and Electronic Documents in mDOC format for EUDI Wallet.

Unlike PKIX, EUDI relies on a centralized model with a single root CA,
EUDI employs a distributed model where all parties are cryptographically bound.
EUDI enforces more rigorous control over attributes (claims), akin to the ABAC model.

CRLs and OCSP can create privacy concerns since they involve
querying a CA, potentially exposing the user's activity.
OpenID4VC mitigates this by enabling the Holder to mediate
the process, and some implementations avoid real-time statu
checks entirely by including cryptographic proofs within the
credential itself.

