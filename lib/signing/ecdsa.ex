defmodule CA.ECDSA.OTP do

  @moduledoc "CA/ECDSA ECC Signature."
  require CA

  # openssl ec -in $client.key -pubout -out $client.pub
  # openssl dgst -sha256 -sign $client.key mix.exs > mix.sig
  # openssl dgst -sha256 -verify $client.pub -signature mix.sig mix.exs
  # CA.ECDSA.sign "mix.exs", "#{client}.key"
  # CA.ECDSA.verify "mix.exs", "mix.sig", "#{client}.pub"
  # CA.ECDSA.OTP.verify "mix.exs", "mix.sig", "#{client}.pub"

  def signBin(msg, priv) do
      CA."ECPrivateKey"(privateKey: point, parameters: {:namedCurve, oid}) = priv
      :crypto.sign(:ecdsa, :sha256, msg,
          [point, :crypto.ec_curve(:pubkey_cert_records.namedCurves(oid))])
  end

  def verifyBin(msg, sig, pub) do
      {CA."ECPoint"(point: point), {:namedCurve, oid}} = pub
      :crypto.verify(:ecdsa, :sha256, msg, sig,
          [point, :crypto.ec_curve(:pubkey_cert_records.namedCurves(oid))])
  end

  def sign(file, priv) do
      {:ok, msg} = :file.read_file file
      {:ok, key} = :file.read_file priv
      signBin(msg, private(key))
  end

  def verify(file, signature, pub) do
      {:ok, msg} = :file.read_file file
      {:ok, sig} = :file.read_file signature
      {:ok, pem} = :file.read_file pub
      verifyBin(msg, sig, public(pem))
  end

  def private(bin), do: :erlang.element(2,X509.PrivateKey.from_pem(bin))
  def public(bin),  do: :public_key.pem_entry_decode(hd(:public_key.pem_decode(bin)))

end
