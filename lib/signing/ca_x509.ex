defmodule CA.X509 do
  @moduledoc "Custom X.509 certificate builder with hardware backend support."

  require Record
  Record.defrecord(:r_OTPCertificate, :OTPCertificate, Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))
  Record.defrecord(:r_OTPTBSCertificate, :OTPTBSCertificate, Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl"))

  @doc """
  Signs a TBSCertificate record using the specified CA private key (hardware or software).
  Returns the DER-encoded certificate.
  """
  def pkix_sign(tbs, ca_key) do
    # 1. Encode TBSCertificate to DER
    der_tbs = :public_key.pkix_encode(:OTPTBSCertificate, tbs, :otp)

    # 2. Extract signature algorithm OID to determine the hashing algorithm
    # In OTPTBSCertificate, signature is field index 3 (0-indexed: version 1, serialNumber 2, signature 3)
    {:SignatureAlgorithm, sig_alg_oid, _} = elem(tbs, 3)

    digest = case sig_alg_oid do
      {1, 2, 840, 10045, 4, 3, 2} -> :sha256
      {1, 2, 840, 10045, 4, 3, 3} -> :sha384
      {1, 2, 840, 10045, 4, 3, 4} -> :sha512
      _ -> :sha384
    end

    # 3. Generate signature using backend
    signature = sign_der(der_tbs, digest, ca_key)

    # 4. Construct OTPCertificate record and encode to DER
    cert = {:OTPCertificate, tbs, elem(tbs, 3), signature}
    :public_key.pkix_encode(:OTPCertificate, cert, :otp)
  end

  @doc """
  Signs a DER block (such as TBSCertificate or TBSCertList) with the active backend.
  """
  def sign_der(der_tbs, digest, {:secure_enclave, label}) do
    hash = :crypto.hash(digest, der_tbs)
    case CA.SecureEnclave.sign(label, hash) do
      {:ok, sig} -> sig
      {:error, reason} -> raise "Secure Enclave signing failed: #{inspect(reason)}"
    end
  end

  def sign_der(der_tbs, digest, {:tpm, handle}) do
    hash = :crypto.hash(digest, der_tbs)
    case CA.TPM.sign(handle, hash) do
      {:ok, sig} -> sig
      {:error, reason} -> raise "TPM signing failed: #{inspect(reason)}"
    end
  end

  def sign_der(der_tbs, digest, ca_key) do
    :public_key.sign(der_tbs, digest, ca_key)
  end

  @doc """
  Builds a new certificate signed by ca_key.
  """
  def new(public_key, subject_rdn, issuer_cert, ca_key, opts \\ []) do
    case ca_key do
      {:secure_enclave, _} ->
        dummy_sign_and_replace(public_key, subject_rdn, issuer_cert, ca_key, opts)
      {:tpm, _} ->
        dummy_sign_and_replace(public_key, subject_rdn, issuer_cert, ca_key, opts)
      _ ->
        X509.Certificate.new(public_key, subject_rdn, issuer_cert, ca_key, opts)
    end
  end

  defp dummy_sign_and_replace(public_key, subject_rdn, issuer_cert, ca_key, opts) do
    temp_key = X509.PrivateKey.new_ec(:secp384r1)
    dummy_cert = X509.Certificate.new(public_key, subject_rdn, issuer_cert, temp_key, opts)
    {:OTPCertificate, tbs, _, _} = dummy_cert
    pkix_sign(tbs, ca_key)
    |> X509.Certificate.from_der!()
  end

  @doc """
  Builds a self-signed root certificate for the given public key, signed by ca_key.
  """
  def self_signed(public_key, ca_key, subject_rdn, opts \\ []) do
    case ca_key do
      {:secure_enclave, _} ->
        self_signed_dummy_and_replace(public_key, ca_key, subject_rdn, opts)
      {:tpm, _} ->
        self_signed_dummy_and_replace(public_key, ca_key, subject_rdn, opts)
      _ ->
        X509.Certificate.self_signed(ca_key, subject_rdn, opts)
    end
  end

  defp self_signed_dummy_and_replace(public_key, ca_key, subject_rdn, opts) do
    temp_key = X509.PrivateKey.new_ec(:secp384r1)
    dummy_cert = X509.Certificate.self_signed(temp_key, subject_rdn, opts)
    {:OTPCertificate, tbs, _, _} = dummy_cert

    # Replace public key in TBSCertificate record
    tbs = put_elem(tbs, 7, X509.PublicKey.wrap(public_key, :OTPSubjectPublicKeyInfo))

    # Update SKI and AKI extensions to match the new public key
    extensions = elem(tbs, 10)
    updated_extensions = update_extensions_for_public_key(extensions, public_key)
    tbs = put_elem(tbs, 10, updated_extensions)

    pkix_sign(tbs, ca_key)
    |> X509.Certificate.from_der!()
  end

  defp update_extensions_for_public_key(extensions, public_key) when is_list(extensions) do
    new_ski = :crypto.hash(:sha, X509.PublicKey.to_der(public_key))
    new_aki_val = {:AuthorityKeyIdentifier, new_ski, :asn1_NOVALUE, :asn1_NOVALUE}

    Enum.map(extensions, fn
      {:Extension, {2, 5, 29, 14}, critical, _} ->
        {:Extension, {2, 5, 29, 14}, critical, new_ski}

      {:Extension, {2, 5, 29, 35}, critical, _} ->
        {:Extension, {2, 5, 29, 35}, critical, new_aki_val}

      other ->
        other
    end)
  end
  defp update_extensions_for_public_key(extensions, _), do: extensions

  @doc """
  Converts a raw EC public key point (65 bytes starting with 0x04) to a PEM SubjectPublicKeyInfo block.
  """
  def raw_to_pem(pub_raw) when byte_size(pub_raw) in [65, 97] do
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
  def raw_to_pem(_), do: {:error, :invalid_pubkey_length}
end
