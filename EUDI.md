EU Digital Identity
===================

SYNRC CA server supports decentralized EUDI issuing architecture.

EUDI Architecture
-----------------

* eIDAS Node -- State Certificate Authority
* EUID Wallet -- iOS/Android Application
* EUDI Provider -- OpenID for Verifiable Credentials (OpenID4VC)
* Personal Identification Data Provider (PP) -- Diia State Enterprise (PID) mDOC
* Attestation Providers (AT) -- Qualified and Non-Qualified Electronic Attestation (QEAA) of Attributes Schema Providers
* Qualifiied Electronic Signature Provider (QP) -- Qualified Certificates (QC)
* EUDI Verifier -- Verifiable Presentations

EUDI model has a similarity with PKIX.
The same way person use a signed attribute set (a X.509 certificate from CSR attributes)
for authentication and authorization in PKI, the OpenID4VC provider (PIP) envelops
set of attributes (digital presentation of claims) and
issue and Electronic Documents in mDOC format for EUDI Wallet.

However, unlike PKIX with its centralized model,
EUDI provide distributed model without single root CA,
where all parties bounded cryptographycally. Also, EUDI has more subtle
and rigorous control over attributes (claims) like in ABAC model.
