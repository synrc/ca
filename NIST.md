# NIST SP 800-53 Control Implementation Details

This document outlines how the **NIST SP 800-53** (Security and Privacy
Controls for Information Systems and Organizations) controls—specifically
those related to **Private Key Storage**—are audited, formulated, and
implemented within the CA application.

## 1. Mapped Controls for Private Key Storage

The newly formulated `CA.NIST.PrivateKeyStorage` profile contains mapped
controls designed to enforce secure cryptographic key management, storage,
transport, and sanitization.

### SC-12: Cryptographic Key Establishment and Management

* **Requirement**: Establish and manage cryptographic keys for required
cryptography using automated mechanisms.

* **Implementation**: The CA application uses Erlang's `:public_key` and `:crypto` modules to automatically establish keys, negotiate curves (like `secp384r1`), and issue/renew certificates dynamically via automated CMP (TCP) and EST (HTTP) protocols.

### SC-12(4): Cryptographic Key Storage (Encryption at Rest)

* **Requirement**: Securely store cryptographic keys.

* **Implementation**:
  * Private keys (`ca.key`, server keys, and client keys) are encrypted using password-based PEM encryption (PKCS#5/PKCS#8) before writing to disk in `CA.CSR.root/2`, `CA.CSR.server/3`, and `CA.CSR.client/3`.
  * The passphrase is dynamically loaded from the application environment configuration (defaulting to the `:password` parameter or `"0000"`).
  * Safe loading wrappers (`X509.PrivateKey.from_pem/2` with password decryption and fallback) are implemented across the CA core and signature engines (`lib/services/csr.ex`, `lib/signing/ecdsa_otp.ex`, `lib/signing/ecdsa.ex`) to decrypt keys dynamically when loaded into memory.

### SC-12(5): Cryptographic Key Destruction

* **Requirement**: Destroy cryptographic keys when no longer required.

* **Implementation**:
  * In the operational environment, keys are removed from disk using Erlang's `:file.delete/1` or Elixir's `File.rm/1`.
  * In test suites, dynamic key cleanup routines are registered with `on_exit` callback hooks to immediately sanitize temporary key directories and prevent local storage pollution.

### SC-13: Cryptographic Protection

* **Requirement**: Implement FIPS-validated cryptography or alternative approved standard ciphers.

* **Implementation**: The signature engines rely on the host's underlying OpenSSL cryptographic provider (compiled with FIPS support) linked dynamically by Erlang's `:crypto` and `:public_key` modules.

### SC-28: Protection of Information at Rest

### SC-28(1): Cryptographic Protection

* **Requirement**: Protect information at rest from unauthorized disclosure and modification.

* **Implementation**: Enforcing key encryption at rest ensures that offline extraction of the CA private key or individual client keys from storage is impossible without the corresponding password.

### MP-4: Media Storage

* **Requirement**: Restrict access to media containing keys and certificates.

* **Implementation**: Key files are written into designated subdirectories (`synrc/ecc/secp384r1/`), allowing administrators to restrict access at the operating system file-system level.

### MP-6: Media Sanitization

* **Requirement**: Sanitize system media prior to disposal or release.

* **Implementation**: All dynamic testing file allocations are completely sanitized and erased at runtime on test completion.

## 2. Security Profile Formulation

The security profile is defined in code as an Elixir module under `lib/cmdb/nist_pks.ex`. It maps standard NIST SP 800-53 controls to the equivalent OIDs in the Security Profile Extensions (SPE) system:

```elixir
defmodule CA.NIST.PrivateKeyStorage do
  @moduledoc "NIST SP 800-53 controls for Private Key Storage"
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Cryptographic Key Establishment and Management
      CA.SPE.oid(:"id-spe-sc-12-4"),  # Cryptographic Key Storage (encryption at rest)
      CA.SPE.oid(:"id-spe-sc-12-5"),  # Cryptographic Key Destruction
      CA.SPE.oid(:"id-spe-sc-13"),    # Cryptographic Protection
      CA.SPE.oid(:"id-spe-sc-28"),    # Protection of Information at Rest
      CA.SPE.oid(:"id-spe-sc-28-1"),  # Cryptographic Protection at Rest
      CA.SPE.oid(:"id-spe-mp-4"),     # Media Storage
      CA.SPE.oid(:"id-spe-mp-6")      # Media Sanitization
    ]
  end
end
```

## 3. General Compliance & Baseline Profiles 53A

In addition to the specific Private Key Storage controls, the application maintains compliance profiles for broader baseline standards under the `lib/cmdb/` directory:
* **Low Baseline**: [nist_low.ex](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_low.ex) maps baseline access controls (AC), awareness training (AT), auditing (AU), system maintenance (MA), and media protection (MP).
* **Moderate Baseline**: [nist_mod.ex](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_mod.ex) includes enhanced system boundaries, key length constraints, and stricter access controls.
* **High Baseline**: [nist_high.ex](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_high.ex) demands cryptographic segregation, dual authorization, and FIPS validation boundaries.

## 4. Secure Enclave Storage — macOS (Hardware Backend)

The `CA.NIST.SecureEnclaveStorage` profile covers hardware-backed key
management via the Apple **Secure Enclave Processor (SEP)**.  The NIF is
implemented in [`c_src/se_nif.c`](file:///Users/tonpa/depot/synrc/ca/c_src/se_nif.c)
and exposed through the Elixir module
[`CA.SecureEnclave`](file:///Users/tonpa/depot/synrc/ca/lib/signing/secure_enclave.ex).

### Key Properties

* Curve: **P-384 / secp384r1** (the only curve the SEP supports — matches `synrc/ecc/secp384r1/ca.key`)
* Storage: macOS Keychain with label `"synrc.ca.secp384r1"` and `kSecAttrTokenIDSecureEnclave`
* Exportability: `kSecAttrIsExtractable = false` — raw key bytes **never** leave the SEP

### SC-12: Cryptographic Key Establishment and Management

* **Requirement**: Establish and manage cryptographic keys using automated mechanisms.
* **Implementation**: `CA.SecureEnclave.generate_key/1` calls `SecKeyGeneratePair` with
  `kSecAttrTokenIDSecureEnclave`; the key pair is created entirely inside the SEP.
  The Keychain label (`"synrc.ca.secp384r1"`) serves as the persistent key identifier
  passed to all subsequent operations.

### SC-12(1): Availability

* **Requirement**: Maintain availability of key material across system restarts.
* **Implementation**: The `kSecAttrIsPermanent = true` attribute writes the key reference
  into the macOS Keychain so it persists across reboots and application restarts without
  any application-layer re-provisioning.

### SC-12(4): Cryptographic Key Storage (Hardware Encryption at Rest)

* **Requirement**: Securely store cryptographic keys using hardware protection.
* **Implementation**: The SEP encrypts every key it holds with its own hardware-fused
  **UID AES-256 key**.  This key is unique per device, burned in at manufacture, and
  inaccessible to the application processor even in DFU mode.  The software fallback
  (`synrc/ecc/secp384r1/ca.key`) may remain for non-macOS environments but is
  superseded on macOS by the SE key.

### SC-12(5): Cryptographic Key Destruction

* **Requirement**: Destroy cryptographic keys when no longer required.
* **Implementation**: `CA.SecureEnclave.delete_key/1` calls `SecItemDelete`, which
  instructs the SEP to erase the key.  Because the key material never left the SEP,
  destruction is immediate and complete with no data remanence.

### SC-13: Cryptographic Protection (FIPS-Validated)

* **Requirement**: Implement FIPS-validated cryptography.
* **Implementation**: The Apple SEP implements P-384 ECDSA at **FIPS 140-2/3 Level 2+**
  (certified under CMVP).  Signing uses `kSecKeyAlgorithmECDSASignatureDigestX962SHA384`
  entirely on-chip; the host CPU handles only the SHA-384 pre-hash and DER signature
  parsing.

### SC-28 / SC-28(1): Protection of Information at Rest

* **Requirement**: Protect key material at rest with cryptographic means.
* **Implementation**: The macOS Keychain entry for the SE key is wrapped with
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, meaning the blob is decrypted by
  the SEP only when the device is unlocked and bound to this specific device — it
  cannot be migrated or read on another machine.

### MP-4: Media Storage

* **Requirement**: Restrict access to media containing key material.
* **Implementation**: The SE key exists only as a Keychain reference (a 32-byte
  persistent token handle), not as a PEM file or DER blob on any filesystem path.
  No removable media can contain the key.

### MP-6: Media Sanitization

* **Requirement**: Sanitize media prior to disposal.
* **Implementation**: `SecItemDelete` instructs the SEP to permanently erase the
  internal key slot.  Even a full device wipe (`Erase All Content and Settings`)
  achieves the same result, as the SEP UID key that wrapped the material is also
  erased — rendering any remnant Keychain blob permanently undecryptable.

```elixir
defmodule CA.NIST.SecureEnclaveStorage do
  @moduledoc "NIST SP 800-53 controls for macOS Secure Enclave P-384 key storage."
  def controls do
    [
      CA.SPE.oid(:"id-spe-sc-12"),    # Key generated inside SEP; label in Keychain
      CA.SPE.oid(:"id-spe-sc-12-1"),  # kSecAttrIsPermanent=true — survives reboots
      CA.SPE.oid(:"id-spe-sc-12-4"),  # SEP AES-256 UID encryption; not extractable
      CA.SPE.oid(:"id-spe-sc-12-5"),  # SecItemDelete permanently destroys SEP key
      CA.SPE.oid(:"id-spe-sc-13"),    # FIPS 140-2/3 Level 2+ P-384 ECDSA in SEP
      CA.SPE.oid(:"id-spe-sc-28"),    # Private key never leaves SEP boundary
      CA.SPE.oid(:"id-spe-sc-28-1"),  # Keychain blob wrapped with AES-256-GCM by SEP
      CA.SPE.oid(:"id-spe-mp-4"),     # Key reference in macOS Keychain (not removable media)
      CA.SPE.oid(:"id-spe-mp-6")      # SecItemDelete irreversible; no data remanence
    ]
  end
end
```

## 5. TPM 2.0 Storage — Linux (Hardware Backend)

The `CA.NIST.TPMStorage` profile covers hardware-backed key management via
a **TPM 2.0** chip on Linux.  The NIF is implemented in
[`c_src/tpm_nif.c`](file:///Users/tonpa/depot/synrc/ca/c_src/tpm_nif.c)
using the **tpm2-tss** ESAPI library, and exposed through the Elixir module
[`CA.TPM`](file:///Users/tonpa/depot/synrc/ca/lib/signing/tpm.ex).

### Key Properties

* Curve: **P-384 / secp384r1** (`TPM2_ECC_NIST_P384`)
* Storage: TPM persistent NV object at handle `0x81010001` (Owner hierarchy slot 1)
* Attributes: `TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT` — key cannot be duplicated or exported

### SC-12: Cryptographic Key Establishment and Management

* **Requirement**: Establish and manage cryptographic keys using automated mechanisms.
* **Implementation**: `CA.TPM.generate_key/1` calls `Esys_CreatePrimary` under
  `ESYS_TR_RH_OWNER`, creating the key entirely inside the TPM.  The resulting
  transient handle is immediately made persistent via `Esys_EvictControl`.

### SC-12(1): Availability

* **Requirement**: Maintain availability of key material across system restarts.
* **Implementation**: `Esys_EvictControl` writes the key to TPM non-volatile storage
  at handle `0x81010001`.  The key persists across reboots, firmware updates, and
  power cycles until explicitly evicted.

### SC-12(4): Cryptographic Key Storage (Hardware Encryption at Rest)

* **Requirement**: Securely store cryptographic keys using hardware protection.
* **Implementation**: `TPMA_OBJECT_FIXEDTPM` prevents key duplication outside the TPM.
  The persistent object blob is wrapped by the **Storage Root Key (SRK)** using the
  TPM's internal AES-256 symmetric engine.  The SRK itself is derived from the TPM's
  hardware-fused **Endorsement Primary Seed (EPS)**, unique to each chip.

### SC-12(5): Cryptographic Key Destruction

* **Requirement**: Destroy cryptographic keys when no longer required.
* **Implementation**: `CA.TPM.delete_key/1` calls `Esys_EvictControl` with
  `ESYS_TR_NONE` as the target handle, which removes the persistent NV entry.
  The TPM immediately frees the NV slot; the SRK-wrapped blob is overwritten.

### SC-13: Cryptographic Protection (FIPS-Validated)

* **Requirement**: Implement FIPS-validated cryptography.
* **Implementation**: TPM 2.0 implementations from major vendors (Infineon, STMicro,
  Nuvoton) are certified at **FIPS 140-2 Level 2**.  Signing uses
  `TPM2_ALG_ECDSA` with `TPM2_ALG_SHA384` entirely on-chip;
  the host CPU only prepares the SHA-384 digest.

### SC-28 / SC-28(1): Protection of Information at Rest

* **Requirement**: Protect key material at rest with cryptographic means.
* **Implementation**: The TPM persistent object blob is encrypted by the SRK under
  the Owner hierarchy.  Only the TPM that created the object can decrypt it —
  migrating the raw NV blob to another machine yields an undecryptable ciphertext.

### MP-4: Media Storage

* **Requirement**: Restrict access to media containing key material.
* **Implementation**: The key is referenced by a 32-bit TPM handle (`0x81010001`).
  No key bytes appear on any filesystem path.  The TPM NV index is accessible
  only through the `/dev/tpm0` or `/dev/tpmrm0` kernel device, protected by
  standard Linux DAC permissions (`root:tss`, mode `0660`).

### MP-6: Media Sanitization

* **Requirement**: Sanitize media prior to disposal.
* **Implementation**: `Esys_EvictControl` removes the NV entry.  For full
  sanitization before hardware disposal, the TPM Owner can issue `TPM2_Clear`,
  which resets the EPS and renders all previously-wrapped blobs permanently
  unrecoverable.

```elixir
defmodule CA.NIST.TPMStorage do
  @moduledoc "NIST SP 800-53 controls for Linux TPM 2.0 P-384 key storage."
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
```

## 6. Cross-Platform Control Comparison

| Control     | Software (PEM)              | macOS Secure Enclave        | Linux TPM 2.0               |
|-------------|-----------------------------|-----------------------------|---------------------------  |
| SC-12       | `:public_key` / `x509` lib  | `SecKeyGeneratePair` in SEP  | `Esys_CreatePrimary` in TPM |
| SC-12(1)    | —                           | `kSecAttrIsPermanent=true`  | `Esys_EvictControl` (NV)    |
| SC-12(4)    | PKCS#8 password encryption  | SEP AES-256 UID key         | SRK AES-256 wrap            |
| SC-12(5)    | `File.rm/1`                 | `SecItemDelete`             | `Esys_EvictControl(NONE)`   |
| SC-13       | OpenSSL (FIPS provider)     | FIPS 140-2/3 L2+ SEP       | FIPS 140-2 L2 TPM           |
| SC-28       | Filesystem permissions      | Key never leaves SEP        | Key never leaves TPM        |
| SC-28(1)    | PEM passphrase (AES-256-CBC)| AES-256-GCM Keychain wrap   | SRK AES-256 NV wrap         |
| MP-4        | `synrc/ecc/secp384r1/`      | Keychain (no FS path)       | `/dev/tpm0` (no FS path)    |
| MP-6        | `File.rm/1` + shred         | `SecItemDelete` irreversible| `Esys_EvictControl` + Clear |

**Module references**:
* Software:       [`CA.NIST.PrivateKeyStorage`](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_pks.ex#L1-L15)
* Secure Enclave: [`CA.NIST.SecureEnclaveStorage`](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_pks.ex#L17-L42) / [`CA.SecureEnclave`](file:///Users/tonpa/depot/synrc/ca/lib/signing/secure_enclave.ex) / [`se_nif.c`](file:///Users/tonpa/depot/synrc/ca/c_src/se_nif.c)
* TPM 2.0:        [`CA.NIST.TPMStorage`](file:///Users/tonpa/depot/synrc/ca/lib/cmdb/nist_pks.ex#L44-L69) / [`CA.TPM`](file:///Users/tonpa/depot/synrc/ca/lib/signing/tpm.ex) / [`tpm_nif.c`](file:///Users/tonpa/depot/synrc/ca/c_src/tpm_nif.c)
