defmodule CA.SE.Software do
  @moduledoc """
  Software fallback for `./synrc/ecc/*/se/` key storage.

  Implements the same folder convention and public API as `CA.SecureEnclave`
  and `CA.TPM`, but uses pure Erlang/OTP cryptography — no NIF, no hardware
  chip required.  Use this on platforms where neither the macOS Secure Enclave
  nor a Linux TPM 2.0 is accessible.

  ## Storage layout: `synrc/ecc/*/se/`

  ```
  synrc/ecc/secp384r1/se/
    se.label   — backend identifier ("software")
    se.key     — PKCS#8 AES-256-CBC encrypted P-384 private key (PEM)
    pub.key    — raw uncompressed EC point (65 bytes: 0x04 ‖ X ‖ Y)
    pub.pem    — PEM SubjectPublicKeyInfo (OpenSSL-readable)
  ```

  `se.key` is encrypted with the application `:password` config value
  (default `"0000"`).  The layout is intentionally identical to the
  hardware backends so `CA.SecureEnclave.detect_backend/1` can select
  this module transparently when hardware is absent.

  ## Backend detection order (`CA.SecureEnclave.detect_backend/1`)

  1. **Secure Enclave** — `se/se.label` contains `"synrc.ca.*"` and macOS NIF loaded
  2. **TPM**            — *(reserved: `tpm/tpm.handle`)*
  3. **Software**       — this module, `se/se.key` present

  ## NIST SP 800-53 Controls

  | Control    | Enforcement                                                    |
  |------------|----------------------------------------------------------------|
  | SC-12      | P-384 key generated via `:crypto.generate_key/2`              |
  | SC-12(4)   | Private key encrypted with PKCS#8 AES-256-CBC before write     |
  | SC-12(5)   | `File.rm!/1` + optional secure-overwrite of `se.key`          |
  | SC-13      | Erlang `:crypto` backed by OpenSSL (FIPS provider if enabled)  |
  | SC-28      | `se.key` encrypted at rest; passphrase not stored in folder    |
  | SC-28(1)   | PKCS#8 AES-256-CBC wrapping of private key material            |
  | MP-4       | Key material in `synrc/ecc/*/se/` (restricted FS path)         |
  | MP-6       | `File.rm!/1` removes key; folder can be wiped on decommission  |

  ## Quick start

      # Provision (generates key, writes se.key + pub.key + pub.pem)
      {:ok, dir} = CA.SE.Software.provision("synrc/ecc/secp384r1/se")

      # Subsequent runs
      {:ok, label} = CA.SE.Software.load("synrc/ecc/secp384r1/se")
      digest = :crypto.hash(:sha384, message)
      {:ok, sig_der} = CA.SE.Software.sign(label, digest)

      # Destroy
      :ok = CA.SE.Software.delete_key(label)
  """

  @label "software"

  # ------------------------------------------------------------------ #
  #  Folder-path helpers (mirror CA.SecureEnclave convention)            #
  # ------------------------------------------------------------------ #

  @doc "Returns the `se.label` path inside `se_dir`."
  @spec label_path(Path.t()) :: Path.t()
  def label_path(se_dir),  do: Path.join(se_dir, "se.label")

  @doc "Returns the encrypted private key path (`se.key`) inside `se_dir`."
  @spec key_path(Path.t()) :: Path.t()
  def key_path(se_dir),    do: Path.join(se_dir, "se.key")

  @doc "Returns the raw public key path (`pub.key`) inside `se_dir`."
  @spec pubkey_path(Path.t()) :: Path.t()
  def pubkey_path(se_dir), do: Path.join(se_dir, "pub.key")

  @doc "Returns the PEM public key path (`pub.pem`) inside `se_dir`."
  @spec pem_path(Path.t()) :: Path.t()
  def pem_path(se_dir),    do: Path.join(se_dir, "pub.pem")

  # ------------------------------------------------------------------ #
  #  Lifecycle                                                           #
  # ------------------------------------------------------------------ #

  @doc """
  Provision a software-backed P-384 key into `se_dir`.

  Generates a fresh P-384 key pair with `:crypto.generate_key/2`,
  encrypts the private key using PKCS#8 AES-256-CBC (passphrase from
  application config `:password`, default `"0000"`), then writes:

  - `se.label` — the string `"software"`
  - `se.key`   — PKCS#8 encrypted PEM (SC-12(4) / SC-28)
  - `pub.key`  — raw 65-byte uncompressed EC point
  - `pub.pem`  — PEM SubjectPublicKeyInfo

  Returns `{:ok, se_dir}` or `{:error, reason}`.

  **SC-12 / SC-12(4) / SC-28 / MP-4**
  """
  @spec provision(Path.t()) :: {:ok, Path.t()} | {:error, term()}
  def provision(se_dir) do
    File.mkdir_p!(se_dir)
    password = password()

    with {pub_key, priv_key}   <- generate_p384(),
         {:ok, priv_pem}        <- encrypt_key(priv_key, password),
         {:ok, pub_raw}         <- export_pub_raw(pub_key),
         {:ok, pub_pem}         <- raw_to_pem(pub_raw),
         :ok                    <- File.write(label_path(se_dir),  @label),
         :ok                    <- File.write(key_path(se_dir),    priv_pem),
         :ok                    <- File.chmod(key_path(se_dir),    0o600),
         :ok                    <- File.write(pubkey_path(se_dir), pub_raw),
         :ok                    <- File.write(pem_path(se_dir),    pub_pem) do
      {:ok, se_dir}
    end
  end

  @doc """
  Load the backend label from `se_dir`.

  For the software backend the label is always `"software"`.  Returns
  `{:ok, "software"}` if the folder is provisioned, or
  `{:error, :not_provisioned}` when `se.label` is absent.
  """
  @spec load(Path.t()) :: {:ok, binary()} | {:error, :not_provisioned | term()}
  def load(se_dir) do
    case File.read(label_path(se_dir)) do
      {:ok, label}      -> {:ok, String.trim(label)}
      {:error, :enoent} -> {:error, :not_provisioned}
      {:error, _} = err -> err
    end
  end

  @doc """
  Returns `true` if `se_dir` has been provisioned (i.e. `se.label` exists).
  """
  @spec provisioned?(Path.t()) :: boolean()
  def provisioned?(se_dir), do: File.exists?(label_path(se_dir))

  # ------------------------------------------------------------------ #
  #  Cryptographic operations                                            #
  # ------------------------------------------------------------------ #

  @doc """
  Sign a 48-byte SHA-384 `digest` using the software key stored in
  `se_dir`.

  The `label` argument is the path to the `se/` folder (returned by
  `load/1` as `"software"`, but callers supply the folder path to
  locate `se.key`).

  Returns `{:ok, signature_der}` (X9.62 DER-encoded ECDSA) or
  `{:error, reason}`.

  **SC-12 / SC-13 / SC-28**
  """
  @spec sign(Path.t(), binary()) :: {:ok, binary()} | {:error, term()}
  def sign(se_dir, digest) when byte_size(digest) == 48 do
    password = password()
    with {:ok, pem}  <- File.read(key_path(se_dir)),
         {:ok, priv} <- decrypt_key(pem, password) do
      {:ECPrivateKey, _, priv_bytes, {:namedCurve, oid}, _} = priv
      curve = :crypto.ec_curve(:pubkey_cert_records.namedCurves(oid))
      sig = :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [priv_bytes, curve])
      {:ok, sig}
    end
  end
  def sign(_se_dir, _digest), do: {:error, :digest_must_be_48_bytes}

  @doc """
  Read back the raw 65-byte uncompressed public key from `pub.key`
  in `se_dir`.

  Returns `{:ok, pub_raw}` or `{:error, reason}`.
  """
  @spec public_key(Path.t()) :: {:ok, binary()} | {:error, term()}
  def public_key(se_dir), do: File.read(pubkey_path(se_dir))

  @doc """
  Permanently destroy the software key stored in `se_dir`.

  Overwrites `se.key` with zero bytes before deleting it (no data
  remanence on standard block devices), then removes `se.label`,
  `pub.key`, and `pub.pem`.

  Returns `:ok` or `{:error, reason}`.

  **SC-12(5) / MP-6**
  """
  @spec delete_key(Path.t()) :: :ok | {:error, term()}
  def delete_key(se_dir) do
    # Zero-overwrite before deletion (best-effort; no guarantee on SSDs)
    key_file = key_path(se_dir)
    case File.stat(key_file) do
      {:ok, %{size: size}} ->
        File.write!(key_file, :binary.copy(<<0>>, size))
      _ -> :ok
    end

    for f <- [key_path(se_dir), label_path(se_dir),
              pubkey_path(se_dir), pem_path(se_dir)] do
      File.rm(f)
    end
    :ok
  end

  # ------------------------------------------------------------------ #
  #  Private helpers                                                     #
  # ------------------------------------------------------------------ #

  defp password do
    :application.get_env(:ca, :password, "0000")
    |> to_string()
  end

  # Generate a P-384 key pair using OTP :crypto.
  defp generate_p384 do
    :crypto.generate_key(:ecdh, :secp384r1)
  end

  # Export the raw uncompressed public key point (04 || X || Y).
  defp export_pub_raw(pub_key) when is_binary(pub_key) and byte_size(pub_key) == 97 do
    # :crypto returns the 97-byte uncompressed point directly for P-384
    {:ok, pub_key}
  end
  defp export_pub_raw(pub_key) when is_binary(pub_key) and byte_size(pub_key) == 65 do
    {:ok, pub_key}
  end
  defp export_pub_raw(_), do: {:error, :unexpected_pubkey_format}

  # Encrypt the private key scalar with PKCS#8 AES-256-CBC via X509 library.
  defp encrypt_key(priv_key_bytes, password) do
    # Build an ECPrivateKey record for X509 serialisation.
    # secp384r1 OID: 1.3.132.0.34
    oid = {1, 3, 132, 0, 34}
    ec_priv = {:ECPrivateKey, 1, priv_key_bytes, {:namedCurve, oid}, :asn1_NOVALUE}
    try do
      pem = X509.PrivateKey.to_pem(ec_priv, password: password)
      {:ok, pem}
    rescue
      e -> {:error, e}
    end
  end

  # Decrypt a PKCS#8 PEM private key.
  defp decrypt_key(pem, password) do
    case X509.PrivateKey.from_pem(pem, password: password) do
      {:ok, key} -> {:ok, key}
      _          ->
        # Fallback: try unencrypted (for dev environments with no password)
        X509.PrivateKey.from_pem(pem)
    end
  end

  # Wrap a 65-byte uncompressed EC point in PEM SubjectPublicKeyInfo for P-384.
  # OID ecPublicKey: 1.2.840.10045.2.1 | OID secp384r1: 1.3.132.0.34
  defp raw_to_pem(pub_raw) when byte_size(pub_raw) in [65, 97] do
    point = if byte_size(pub_raw) == 97, do: binary_part(pub_raw, 0, 65), else: pub_raw
    # DER SEQUENCE { SEQUENCE { OID ecPublicKey, OID secp384r1 } BIT STRING }
    spki = <<
      0x30, 0x76,
      0x30, 0x10,
      0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,  # ecPublicKey
      0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,               # secp384r1
      0x03, 0x62, 0x00                                          # BIT STRING
    >> <> point
    b64 = Base.encode64(spki, padding: true)
    chunks = for <<c::binary-64 <- b64>>, do: c
    rem = rem(byte_size(b64), 64)
    chunks = if rem > 0, do: chunks ++ [binary_part(b64, byte_size(b64) - rem, rem)], else: chunks
    pem = [
      "-----BEGIN PUBLIC KEY-----\n",
      Enum.map(chunks, &(&1 <> "\n")),
      "-----END PUBLIC KEY-----\n"
    ]
    {:ok, IO.iodata_to_binary(pem)}
  end
  defp raw_to_pem(_), do: {:error, :invalid_pubkey_length}
end
