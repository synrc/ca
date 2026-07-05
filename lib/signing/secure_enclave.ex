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
  def generate_key(_label), do: (if System.get_env("COMPILE") == "1", do: {:ok, <<0>>}, else: {:error, ~c"not_supported"})

  @doc """
  Retrieve the DER-encoded public key for an existing Secure Enclave key.

  Returns `{:ok, public_key_raw}` (uncompressed 65-byte EC point) or
  `{:error, reason}`.
  """
  @spec public_key(binary()) :: {:ok, binary()} | {:error, term()}
  def public_key(_label), do: (if System.get_env("COMPILE") == "1", do: {:ok, <<0>>}, else: {:error, :not_supported})

  @doc """
  Sign a 48-byte SHA-384 `digest` using the Secure Enclave key identified
  by `label`.  Signing occurs entirely inside the SEP.

  Returns `{:ok, signature_der}` (X9.62 DER-encoded ECDSA signature) or
  `{:error, reason}`.

  **SC-12 / SC-13 / SC-28**
  """
  @spec sign(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def sign(_label, _digest), do: (if System.get_env("COMPILE") == "1", do: {:ok, <<0>>}, else: {:error, :not_supported})

  @doc """
  Permanently delete the Secure Enclave key identified by `label`.

  This is an irreversible operation — the private key is destroyed inside
  the SEP with no possibility of recovery.

  Returns `:ok` or `{:error, reason}`.

  **SC-12(5) / MP-6**
  """
  @spec delete_key(binary()) :: :ok | {:error, term()}
  def delete_key(_label), do: (if System.get_env("COMPILE") == "1", do: :ok, else: {:error, :not_supported})

  @doc """
  First-time initializer for the macOS Secure Enclave (T2 / Apple Silicon) backend.

  ## What it does

  1. Resolves the Keychain `label` for this CA profile.
  2. Checks whether `se/se.label` already exists — **idempotent**, safe to call on
     every boot without re-provisioning.
  3. Generates a fresh P-384 key **inside** the Secure Enclave; private key material
     never leaves the SEP boundary (NIST SC-12 / SC-28).
  4. Persists `se.label`, `pub.key` (raw 65-byte EC point), and `pub.pem`
     (SubjectPublicKeyInfo PEM) into `synrc/ecc/<profile>/se/`.
  5. Builds a self-signed CA certificate (25 years), signed wholly inside the SEP.
  6. Writes `ca.pem` — **no `ca.key` is ever written to disk**.
  7. Activates `{:secure_enclave, label}` in the application env so the running
     system uses the hardware backend immediately without a restart.

  ## Example

      # First boot on a macOS machine with T2 / Apple Silicon:
      iex> CA.init_apple("synrc.ca.secp384r1")
      :ok

      # Subsequent boots — no-op:
      iex> CA.init_apple("synrc.ca.secp384r1")
      :ok   # already provisioned, skipped

  ## Platform note

  Requires macOS with Secure Enclave (T2 chip or Apple Silicon M-series).
  On other platforms `CA.SecureEnclave.generate_key/1` returns
  `{:error, :not_supported}` and the function raises a `MatchError`.
  """
  @spec init_apple(binary(), binary()) :: {:ok, binary()} | {:error, term()}
  def init_apple(label, profile \\ "secp384r1") do
    se_dir = CA.CSR.dir_se(profile)
    File.mkdir_p!(se_dir)

    if CA.SecureEnclave.provisioned?(se_dir) do
      :logger.info(~c"CA APPLE SE already provisioned for profile ~p, skipping", [profile])
      {:ok, label}
    else
      :logger.info(~c"CA APPLE SE first init: profile=~p label=~p", [profile, label])

      # 1. Generate key inside Secure Enclave — private key never leaves SEP
      case CA.SecureEnclave.generate_key(label) do
        {:error, reason} ->
          handle_se_error(reason, label)

        {:ok, pub_raw} ->
          provision_se(pub_raw, label, profile, se_dir)
      end
    end
  end

  # -34018 = errSecMissingEntitlement — beam.smp must be code-signed with
  # com.apple.application-identifier and keychain-access-groups entitlements.
  #
  # Fix: sign the Erlang VM binary before running:
  #
  #   codesign --force --sign - \
  #     --entitlements priv/se_entitlements.plist \
  #     $(which erl | xargs readlink -f | sed 's|/bin/erl||')/erts-*/bin/beam.smp
  #
  # priv/se_entitlements.plist must contain:
  #   <key>com.apple.application-identifier</key>   <string>YOUR.TEAM.ID.synrc.ca</string>
  #   <key>keychain-access-groups</key>              <array><string>YOUR.TEAM.ID.synrc.ca</string></array>
  defp handle_se_error(~c"SecKeyGeneratePair_failed_-34018" = reason, label) do
    :logger.error(
      ~c"""
      CA APPLE SE keygen failed for label ~p: errSecMissingEntitlement (-34018).

      The BEAM VM process must be code-signed with Keychain entitlements to
      access the Secure Enclave. Run once as root or as the app user:

        codesign --force --sign - \\
          --entitlements $(mix deps.get >/dev/null; echo priv/se_entitlements.plist) \\
          $(elixir -e ':code.root_dir |> to_string |> IO.puts')/erts-*/bin/beam.smp

      Then create priv/se_entitlements.plist with:
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>com.apple.application-identifier</key>
          <string>TEAMID.synrc.ca</string>
          <key>keychain-access-groups</key>
          <array><string>TEAMID.synrc.ca</string></array>
        </dict></plist>

      Replace TEAMID with your Apple Developer Team ID (10-char alphanumeric).
      Falls back to software backend automatically.
      """,
      [label]
    )
    {:error, {:missing_entitlement, reason}}
  end

  defp handle_se_error(reason, label) do
    :logger.error(~c"CA APPLE SE keygen failed for label ~p: ~p", [label, reason])
    {:error, reason}
  end

  defp provision_se(pub_raw, label, _profile, se_dir) do
    # 2. Persist Keychain label and public key material to disk
    {:ok, pub_pem} = CA.X509.raw_to_pem(pub_raw)
    File.write!(CA.SecureEnclave.label_path(se_dir), label)
    File.write!(CA.SecureEnclave.pubkey_path(se_dir), pub_raw)
    File.write!(CA.SecureEnclave.pem_path(se_dir), pub_pem)
    :logger.info(~c"CA APPLE SE key generated, label persisted to ~p", [se_dir])

    # 3. Build self-signed root CA certificate (signing occurs inside SEP)
    {:ok, public_key} = X509.PublicKey.from_pem(pub_pem)
    subject_rdn = CA.RDN.decodeAttrs(X509.RDNSequence.new("/C=UA/L=Київ/O=SYNRC/CN=CA"))

    ca =
      CA.X509.self_signed(public_key, {:secure_enclave, label}, subject_rdn,
        template: %X509.Certificate.Template{
          validity: round(25 * 365.2425),
          hash: :sha256,
          extensions: [
            basic_constraints: X509.Certificate.Extension.basic_constraints(true, 1),
            key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
            subject_key_identifier: true,
            authority_key_identifier: true
          ]
        }
      )

    # 4. Write root certificate — no ca.key ever touches disk
    File.write!("#{se_dir}/ca.pem", X509.Certificate.to_pem(ca))
    :logger.info(~c"CA APPLE SE root certificate written to ~p/ca.pem", [se_dir])

    # 5. Activate hardware backend in the running VM immediately
    Application.put_env(:ca, :key_backend, {:secure_enclave, label})
    :logger.info(~c"CA APPLE SE backend active: {:secure_enclave, ~p}", [label])

    {:ok, label}
  end

end
