defmodule CA.NIST.PrivateKeyStorage do
  @moduledoc "NIST SP 800-53 controls for Private Key Storage (software, password-encrypted PEM)"
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Cryptographic Key Establishment and Management
      CA.SPE.oid(:"id-spe-sc-12-4"),  # Cryptographic Key Storage (encryption at rest)
      CA.SPE.oid(:"id-spe-sc-12-5"),  # Cryptographic Key Destruction
      CA.SPE.oid(:"id-spe-sc-13"),    # Cryptographic Protection (FIPS-validated)
      CA.SPE.oid(:"id-spe-sc-28"),    # Protection of Information at Rest
      CA.SPE.oid(:"id-spe-sc-28-1"),  # Cryptographic Protection at Rest
      CA.SPE.oid(:"id-spe-mp-4"),     # Media Storage
      CA.SPE.oid(:"id-spe-mp-6")      # Media Sanitization
    ]
  end
end

defmodule CA.NIST.SecureEnclaveStorage do
  @moduledoc """
  NIST SP 800-53 controls for macOS Secure Enclave P-384 key storage.

  Implemented by `CA.SecureEnclave` NIF (`c_src/se_nif.c`).
  The CA private key for `synrc/ecc/secp384r1/ca.key` is generated and
  retained inside the Apple Secure Enclave Processor (SEP); it never
  reaches the application processor in plaintext.

  Hardware backend: macOS Security.framework / kSecAttrTokenIDSecureEnclave
  Keychain label convention: \"synrc.ca.secp384r1\"

  ## Storage layout: `synrc/ecc/*/se/`

  Public artifacts are written to a dedicated subfolder by `CA.SecureEnclave.provision/1`:

      synrc/ecc/secp384r1/se/
        se.label   — Keychain label (UTF-8)
        pub.key    — raw 65-byte uncompressed EC point
        pub.pem    — PEM SubjectPublicKeyInfo (OpenSSL-readable)

  The private key is NEVER stored here or anywhere on disk.
  """
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Key generated inside SEP; label in Keychain
      CA.SPE.oid(:"id-spe-sc-12-1"),  # kSecAttrIsPermanent=true — survives reboots
      CA.SPE.oid(:"id-spe-sc-12-4"),  # SEP AES-256 UID encryption; not extractable
      CA.SPE.oid(:"id-spe-sc-12-5"),  # SecItemDelete permanently destroys SEP key
      CA.SPE.oid(:"id-spe-sc-13"),    # FIPS 140-2/3 Level 2+ P-384 ECDSA in SEP
      CA.SPE.oid(:"id-spe-sc-28"),    # Private key never leaves SEP boundary
      CA.SPE.oid(:"id-spe-sc-28-1"),  # Keychain blob wrapped with AES-256-GCM by SEP
      CA.SPE.oid(:"id-spe-mp-4"),     # Public artifacts in synrc/ecc/secp384r1/se/ (no private key)
      CA.SPE.oid(:"id-spe-mp-6")      # SecItemDelete irreversible; se/ folder deletable safely
    ]
  end
end

defmodule CA.NIST.TPMStorage do
  @moduledoc """
  NIST SP 800-53 controls for Linux TPM 2.0 P-384 key storage.

  Implemented by `CA.TPM` NIF (`c_src/tpm_nif.c`) via the tpm2-tss ESAPI.
  The CA private key is created as a persistent TPM object under the Owner
  hierarchy and protected by the Storage Root Key (SRK).  It never leaves
  the TPM boundary in plaintext.

  Hardware backend: tss2-esys / TPM2_ECC_NIST_P384
  Default persistent handle: 0x81010001 (Owner hierarchy slot 1)
  """
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Key created inside TPM under Owner hierarchy
      CA.SPE.oid(:"id-spe-sc-12-1"),  # Persistent NV handle — survives reboots
      CA.SPE.oid(:"id-spe-sc-12-4"),  # TPMA_OBJECT_FIXEDTPM — encrypted by SRK
      CA.SPE.oid(:"id-spe-sc-12-5"),  # Esys_EvictControl destroys persistent object
      CA.SPE.oid(:"id-spe-sc-13"),    # FIPS 140-2 Level 2 TPM P-384 ECDSA
      CA.SPE.oid(:"id-spe-sc-28"),    # Private key never exposed outside TPM
      CA.SPE.oid(:"id-spe-sc-28-1"),  # TPM NV storage encrypted by internal SRK AES-256
      CA.SPE.oid(:"id-spe-mp-4"),     # Key referenced by 32-bit handle (no FS exposure)
      CA.SPE.oid(:"id-spe-mp-6")      # Esys_EvictControl irreversible; no remanence
    ]
  end
end
