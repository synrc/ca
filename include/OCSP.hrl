%% Generated by the Erlang ASN.1 compiler. Version: 5.1
%% Purpose: Erlang record definitions for each named and unnamed
%% SEQUENCE and SET, and macro definitions for each value
%% definition in module OCSP.

-ifndef(_OCSP_HRL_).
-define(_OCSP_HRL_, true).

-record('OCSPRequest', {
  tbsRequest,
  optionalSignature = asn1_NOVALUE
}).

-record('TBSRequest', {
  version = asn1_DEFAULT,
  requestorName = asn1_NOVALUE,
  requestList,
  requestExtensions = asn1_NOVALUE
}).

-record('Signature', {
  signatureAlgorithm,
  signature,
  certs = asn1_NOVALUE
}).

-record('Request', {
  reqCert,
  singleRequestExtensions = asn1_NOVALUE
}).

-record('CertID', {
  hashAlgorithm,
  issuerNameHash,
  issuerKeyHash,
  serialNumber
}).

-record('OCSPResponse', {
  responseStatus,
  responseBytes = asn1_NOVALUE
}).

-record('ResponseBytes', {
  responseType,
  response
}).

-record('BasicOCSPResponse', {
  tbsResponseData,
  signatureAlgorithm,
  signature,
  certs = asn1_NOVALUE
}).

-record('ResponseData', {
  version = asn1_DEFAULT,
  responderID,
  producedAt,
  responses,
  responseExtensions = asn1_NOVALUE
}).

-record('SingleResponse', {
  certID,
  certStatus,
  thisUpdate,
  nextUpdate = asn1_NOVALUE,
  singleExtensions = asn1_NOVALUE
}).

-record('RevokedInfo', {
  revocationTime,
  revocationReason = asn1_NOVALUE
}).

-record('ServiceLocator', {
  issuer,
  locator
}).

-define('id-pkix-ocsp', {1,3,6,1,5,5,7,48,1}).
-define('id-pkix-ocsp-basic', {1,3,6,1,5,5,7,48,1,1}).
-define('id-pkix-ocsp-nonce', {1,3,6,1,5,5,7,48,1,2}).
-define('id-pkix-ocsp-crl', {1,3,6,1,5,5,7,48,1,3}).
-define('id-pkix-ocsp-response', {1,3,6,1,5,5,7,48,1,4}).
-define('id-pkix-ocsp-nocheck', {1,3,6,1,5,5,7,48,1,5}).
-define('id-pkix-ocsp-archive-cutoff', {1,3,6,1,5,5,7,48,1,6}).
-define('id-pkix-ocsp-service-locator', {1,3,6,1,5,5,7,48,1,7}).
-endif. %% _OCSP_HRL_
