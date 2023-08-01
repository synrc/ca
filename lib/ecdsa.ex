defmodule CA.ECDSA do
  @moduledoc "CA/ECDSA ECC Signature."
  require CA

  # openssl dgst -sha256 -sign $client.key mix.exs > mix.sig
  # openssl dgst -sha256 -verify $client.pub -signature mix.sig mix.exs
  # CA.ECDSA.verify "mix.exs", "mix.sig", "#{client}.pub"

  def verify(file, signature, pem) do
      {:ok, msg} = :file.read_file file
      {:ok, sig} = :file.read_file signature
      verifyBin(msg, sig, public(pem))
  end

  def verifyBin(msg, sig, public) do
      {CA."ECPoint"(point: point), {_namedCurve, oid}} = public
      :crypto.verify(:ecdsa, :sha256, msg, sig,
        [point, :crypto.ec_curve(:pubkey_cert_records.namedCurves(oid))])
  end

  def public(name) do
      :public_key.pem_entry_decode(hd(:public_key.pem_decode(
      :erlang.element(2, :file.read_file( name )))))
  end

end
