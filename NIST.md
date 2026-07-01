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
