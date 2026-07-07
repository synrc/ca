defmodule CA.TPM do
  def generate_key(_), do: (if System.get_env("COMPILE") == "1", do: {:ok, <<0>>}, else: {:error, :tpm_disabled})
  def sign(_, _), do: (if System.get_env("COMPILE") == "1", do: {:ok, <<0>>}, else: {:error, :tpm_disabled})
  def delete_key(_), do: (if System.get_env("COMPILE") == "1", do: :ok, else: {:error, :tpm_disabled})
end

defmodule CA.TPM2 do
  @moduledoc """
  NIF wrapper for Linux TPM 2.0 P-384 key storage.

  All private key operations (generation, signing, deletion) execute
  **inside** the TPM hardware module via the tpm2-tss ESAPI.  Private
  key material is protected by the TPM Storage Root Key (SRK) and never
  leaves the TPM boundary in plaintext.

  Keys are stored as **persistent objects** at a 32-bit TPM handle
  (default: `0x81010001`).  The handle survives reboots, power cycles,
  and firmware updates unless explicitly evicted.

  ## NIST SP 800-53 Controls

  | Control   | Enforcement                                                   |
  |-----------|---------------------------------------------------------------|
  | SC-12     | Key pair created inside TPM under Owner hierarchy             |
  | SC-12(1)  | Persistent NV handle (0x81xxxxxx) — survives reboots          |
  | SC-12(4)  | `TPMA_OBJECT_FIXEDTPM` — encrypted by SRK; not extractable   |
  | SC-12(5)  | `Esys_EvictControl` with ESYS_TR_NONE destroys the key        |
  | SC-13     | FIPS 140-2 Level 2 TPM P-384 ECDSA (TPM2_ECC_NIST_P384)      |
  | SC-28     | Private key never exposed outside TPM boundary                |
  | SC-28(1)  | TPM NV storage encrypted by internal SRK AES-256              |
  | MP-4      | Key referenced by 32-bit TPM handle (no filesystem exposure)  |
  | MP-6      | `Esys_EvictControl` is irreversible; no data remanence        |

  ## Usage

      iex> handle = 0x81010001
      iex> {:ok, pub_raw} = CA.TPM.generate_key(handle)
      iex> digest = :crypto.hash(:sha384, "data")
      iex> {:ok, sig_der} = CA.TPM.sign(handle, digest)
      iex> :ok = CA.TPM.delete_key(handle)

  ## Key Handle Convention

  By default the CA root key occupies handle `0x81010001`.  Additional
  handles (e.g. `0x81010002` for intermediate keys) can be managed
  with the same API.  Record handles in your operational key registry.

  ## Platform Support

  This module loads `priv/tpm_nif.so` on Linux with a physical or
  emulated TPM 2.0 device at `/dev/tpm0` or `/dev/tpmrm0`.
  On other platforms all functions return `{:error, :not_supported}`.
  Use `CA.SecureEnclave` for macOS hardware-backed storage.

  ## Linux Prerequisites

      # Debian / Ubuntu
      apt-get install libtss2-esys-dev libtss2-mu-dev libtss2-rc-dev
      # Arch
      pacman -S tpm2-tss
      # Fedora
      dnf install tpm2-tss-devel
  """

  @nif_path :filename.join(:code.priv_dir(:ca), ~c"tpm_nif")

  @on_load :load_nif

  @doc false
  def load_nif do
    case :os.type() do
      {:unix, :linux} ->
        so_file = @nif_path ++ ~c".so"
        if :filelib.is_regular(so_file) do
          :erlang.load_nif(@nif_path, 0)
        else
          :ok
        end
      _               -> :ok
    end
  end

  @doc """
  Generate a new P-384 key inside the TPM and persist it at
  `persistent_handle` (a 32-bit integer in the range `0x81010000–0x8101FFFF`).

  Returns `{:ok, public_key_raw}` where `public_key_raw` is the
  uncompressed EC point (65 bytes: `0x04 || X || Y`), or
  `{:error, reason}` on failure.

  **SC-12 / SC-12(1) / SC-12(4)**
  """
  @spec generate_key(non_neg_integer()) :: {:ok, binary()} | {:error, term()}
  def generate_key(_handle), do: {:error, :not_supported}

  @doc """
  Retrieve the uncompressed public key (65 bytes) for the TPM key at
  `persistent_handle`.

  Returns `{:ok, public_key_raw}` or `{:error, reason}`.
  """
  @spec public_key(non_neg_integer()) :: {:ok, binary()} | {:error, term()}
  def public_key(_handle), do: {:error, :not_supported}

  @doc """
  Sign a 48-byte SHA-384 `digest` using the TPM key at `persistent_handle`.
  Signing occurs entirely inside the TPM.

  Returns `{:ok, signature_der}` (X9.62 DER-encoded ECDSA signature) or
  `{:error, reason}`.

  **SC-12 / SC-13 / SC-28**
  """
  @spec sign(non_neg_integer(), binary()) :: {:ok, binary()} | {:error, term()}
  def sign(_handle, _digest), do: {:error, :not_supported}

  @doc """
  Permanently evict the TPM key at `persistent_handle`.

  This is irreversible — the key is removed from TPM non-volatile storage
  and cannot be recovered.

  Returns `:ok` or `{:error, reason}`.

  **SC-12(5) / MP-6**
  """
  @spec delete_key(non_neg_integer()) :: :ok | {:error, term()}
  def delete_key(_handle), do: {:error, :not_supported}
end
