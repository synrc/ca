defmodule CA.AT do
  @moduledoc "CA CSR Attributes OIDs."
  def oid(:"id-at-rsaEncryption"),                        do: {1, 2, 840, 113549, 1, 1, 1}
  def oid(:"id-at-sha1WithRSAEncryption"),                do: {1, 2, 840, 113549, 1, 1, 5}
  def oid(:"id-at-sha512-256WithRSAEncryption"),          do: {1, 2, 840, 113549, 1, 1, 16}
  def oid(:"id-at-dhKeyAgreement"),                       do: {1, 2, 840, 113549, 1, 3, 1}
  def oid(:"id-at-emailAddress"),                         do: {1, 2, 840, 113549, 1, 9, 1}
  def oid(:"id-at-unstructuredName"),                     do: {1, 2, 840, 113549, 1, 9, 2}
  def oid(:"id-at-contentType"),                          do: {1, 2, 840, 113549, 1, 9, 3}
  def oid(:"id-at-messageDigest"),                        do: {1, 2, 840, 113549, 1, 9, 4}
  def oid(:"id-at-signingTime"),                          do: {1, 2, 840, 113549, 1, 9, 5}
  def oid(:"id-at-counterSignature"),                     do: {1, 2, 840, 113549, 1, 9, 6}
  def oid(:"id-at-challengePassword"),                    do: {1, 2, 840, 113549, 1, 9, 7}
  def oid(:"id-at-unstructuredAddress"),                  do: {1, 2, 840, 113549, 1, 9, 8}
  def oid(:"id-at-extendedCertificateAttributes"),        do: {1, 2, 840, 113549, 1, 9, 9}
  def oid(:"id-at-issuerAndSerialNumber"),                do: {1, 2, 840, 113549, 1, 9, 10}
  def oid(:"id-at-passwordCheck"),                        do: {1, 2, 840, 113549, 1, 9, 11}
  def oid(:"id-at-publicKey"),                            do: {1, 2, 840, 113549, 1, 9, 12}
  def oid(:"id-at-signingDescription"),                   do: {1, 2, 840, 113549, 1, 9, 13}
  def oid(:"id-at-extensionRequest"),                     do: {1, 2, 840, 113549, 1, 9, 14}
  def oid(:"id-at-smimeCapabilities"),                    do: {1, 2, 840, 113549, 1, 9, 15}
end