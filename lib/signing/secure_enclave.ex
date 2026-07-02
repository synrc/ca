defmodule CA.SecureEnclave do
  @moduledoc """
  NIF wrapper for macOS Secure Enclave P-384 key storage.

  All private key operations (generation, signing, deletion) execute
  **inside** the Secure Enclave Processor (SEP).  Private key material
  never reaches the application processor in any readable form.

  ## NIST SP 800-53 Controls

  | Control   | Enforcement                                                   |
  |-----------|---------------------------------------------------------------|
  | SC-12     | Key pair generated inside SEP; Keychain label persisted       |
  | SC-12(1)  | `kSecAttrIsPermanent=true` — key survives reboots             |
  | SC-12(4)  | `kSecAttrTokenIDSecureEnclave` — AES-256 hardware encryption  |
  | SC-12(5)  | `SecItemDelete` permanently destroys the SEP key              |
  | SC-13     | FIPS 140-2/3 Level 2+ P-384 ECDSA executed in SEP            |
  | SC-28     | Private key never leaves the SEP boundary                     |
  | SC-28(1)  | Keychain blob wrapped with AES-256-GCM by SEP                 |
  | MP-4      | Key reference stored in macOS Keychain (not removable media)  |
  | MP-6      | `SecItemDelete` is irreversible; no data remanence in SEP     |

  ## Usage

      iex> label = "synrc.ca.secp384r1"
      iex> {:ok, pub_raw} = CA.SecureEnclave.generate_key(label)
      iex> digest = :crypto.hash(:sha384, "data")
      iex> {:ok, sig_der} = CA.SecureEnclave.sign(label, digest)
      iex> :ok = CA.SecureEnclave.delete_key(label)

  ## Platform Support

  This module loads `priv/se_nif.dylib` on macOS.  On other platforms
  the NIF load is skipped and all functions return `{:error, :not_supported}`.
  Use `CA.TPM` for Linux hardware-backed storage.
  """

  # Platform-specific NIF library extension
  @nif_ext (case :os.type() do {:unix, :darwin} -> ~c".dylib" ; _ -> ~c".so" end)
  @nif_path :filename.join(:code.priv_dir(:ca), ~c"se_nif" ++ @nif_ext)

  # ------------------------------------------------------------------ #
  #  Pure-Elixir folder helpers — available on all platforms             #
  #  (defined BEFORE @on_load so they work even if NIF load fails)       #
  # ------------------------------------------------------------------ #

  @doc "Returns the `se.label` path inside `se_dir`."
  @spec label_path(Path.t()) :: Path.t()
  def label_path(se_dir),  do: Path.join(se_dir, "se.label")

  @doc "Returns the raw public key path (`pub.key`) inside `se_dir`."
  @spec pubkey_path(Path.t()) :: Path.t()
  def pubkey_path(se_dir), do: Path.join(se_dir, "pub.key")

  @doc "Returns the PEM public key path (`pub.pem`) inside `se_dir`."
  @spec pem_path(Path.t()) :: Path.t()
  def pem_path(se_dir),    do: Path.join(se_dir, "pub.pem")

  @doc """
  Load the Keychain label from an existing `se_dir` folder.
  Returns `{:ok, label}` or `{:error, :not_provisioned}`.
  """
  @spec load(Path.t()) :: {:ok, binary()} | {:error, :not_provisioned | term()}
  def load(se_dir) do
    case File.read(label_path(se_dir)) do
      {:ok, label}      -> {:ok, String.trim(label)}
      {:error, :enoent} -> {:error, :not_provisioned}
      {:error, _} = err -> err
    end
  end

  @doc "Returns `true` if `se_dir` has been provisioned."
  @spec provisioned?(Path.t()) :: boolean()
  def provisioned?(se_dir), do: File.exists?(label_path(se_dir))

  @doc """
  Select the active key backend for a given curve directory.

  Priority:
  1. **Secure Enclave** — `se/se.label` exists (macOS).
  2. **Software** — falls back to `se/ca.key`.

  Returns `{:secure_enclave, label}` or `{:software, key_path}`.
  """
  @spec detect_backend(Path.t()) :: {:secure_enclave, binary()} | {:software, Path.t()}
  def detect_backend(curve_dir \\ "synrc/ecc/secp384r1") do
    se_dir = Path.join(curve_dir, "se")
    case load(se_dir) do
      {:ok, label} -> {:secure_enclave, label}
      _            -> {:software, Path.join(se_dir, "ca.key")}
    end
  end

  @on_load :load_nif

  @doc false
  def load_nif do
    case :os.type() do
      {:unix, :darwin} -> :erlang.load_nif(@nif_path, 0)
      _                -> :ok
    end
  end

  @doc """
  Generate a new P-384 key inside the Secure Enclave and store it under
  the given Keychain `label`.

  Returns `{:ok, public_key_raw}` where `public_key_raw` is the
  uncompressed EC point (65 bytes: `0x04 || X || Y`), or
  `{:error, reason}` on failure.

  **SC-12 / SC-12(1) / SC-12(4)**
  """
  @spec generate_key(binary()) :: {:ok, binary()} | {:error, term()}
  def generate_key(_label), do: {:error, :not_supported}

  @doc """
  Retrieve the DER-encoded public key for an existing Secure Enclave key.

  Returns `{:ok, public_key_raw}` (uncompressed 65-byte EC point) or
  `{:error, reason}`.
  """
  @spec public_key(binary()) :: {:ok, binary()} | {:error, term()}
  def public_key(_label), do: {:error, :not_supported}

  @doc """
  Sign a 48-byte SHA-384 `digest` using the Secure Enclave key identified
  by `label`.  Signing occurs entirely inside the SEP.

  Returns `{:ok, signature_der}` (X9.62 DER-encoded ECDSA signature) or
  `{:error, reason}`.

  **SC-12 / SC-13 / SC-28**
  """
  @spec sign(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def sign(_label, _digest), do: {:error, :not_supported}

  @doc """
  Permanently delete the Secure Enclave key identified by `label`.

  This is an irreversible operation — the private key is destroyed inside
  the SEP with no possibility of recovery.

  Returns `:ok` or `{:error, reason}`.

  **SC-12(5) / MP-6**
  """
  @spec delete_key(binary()) :: :ok | {:error, term()}
  def delete_key(_label), do: {:error, :not_supported}
end
