defmodule CA do
  @moduledoc """
  The main CA module implements Elixir application functionality
  that runs TCP and HTTP connections under Erlang/OTP supervision.
  """
  use Application

  def port(app) do
    Application.fetch_env!(:ca, app)
  end

  def start(_type, _args) do
    :logger.add_handlers(:ca)

    # Detect and persist the active key backend so all modules use the same one
    backend = CA.SecureEnclave.detect_backend()
    Application.put_env(:ca, :key_backend, backend)
    :logger.info(~c"CA KEY BACKEND: ~p", [backend])

    # Initialize CA key material for all configured curve profiles
    profiles = Application.get_env(:ca, :profiles, ["secp384r1"])
    Enum.each(profiles, fn profile ->
      :logger.info(~c"CA INIT PROFILE: ~p", [profile])
      CA.CSR.init(profile)
    end)

    Supervisor.start_link(
      [
        {Task.Supervisor, name: CA.TaskSupervisor},
        {CA.CMP, port: port(:cmp)},
        {CA.CMC, port: port(:cmc)},
        {CA.OCSP, port: port(:ocsp)},
        {CA.TSP, port: port(:tsp)},
        #        { CA.EUDI.Issuer, port: port(:issuer), plug: CA.EUDI.Issuer, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        #        { CA.EUDI.Verifier, port: port(:verifier), plug: CA.EUDI.Verifier, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        #        { CA.EUDI.Wallet, port: port(:wallet), plug: CA.EUDI.Wallet, scheme: :http, thousand_island_options: [num_acceptors: 1] },
        {CA.EST, port: port(:est), plug: CA.EST, scheme: :http, thousand_island_options: [num_acceptors: 1]}
      ], strategy: :one_for_one, name: CA.Supervisor)
  end

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
