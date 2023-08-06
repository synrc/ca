defmodule CA.ECDSA do
  require CA.Point
  require CA.Integer
  require CA.Jacobian
  require CA.ECDSA.OTP

  def numberFromString(data) do
      Base.encode16(data)
      |> Integer.parse(16)
      |> (fn {parsedInt, ""} -> parsedInt end).()
  end

  def sign(message, privateKey, options \\ []) do
      %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})
      number = :crypto.hash(hashfunc, message) |> numberFromString()
      curve = CA.KnownCurves.secp256k1()
      randNum = CA.Integer.between(1, curve."N" - 1)
      r = CA.Jacobian.multiply(curve."G", randNum, curve."N", curve."A", curve."P").x
        |> CA.Integer.modulo(curve."N")
      s = ((number + r * privateKey) * CA.Jacobian.inv(randNum, curve."N"))
        |> CA.Integer.modulo(curve."N")
      {r, s}
  end

  def private(bin), do: :erlang.element(2,X509.PrivateKey.from_pem(bin))
  def public(bin),  do: #:erlang.element(1,:erlang.element(2,
                        :public_key.pem_entry_decode(hd(:public_key.pem_decode(bin)))

  def verify(file, signature, pub) do
      {:ok, msg} = :file.read_file file
      {:ok, pem} = :file.read_file pub
      verify(msg, CA.ECDSA.OTP.signature(signature), public(pem), [])
  end

  def verify(message, {r,s}, publicKey, options) do
      %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})
      number = :crypto.hash(hashfunc, message) |> numberFromString()
      curve = CA.KnownCurves.secp256k1()
      inv = CA.Jacobian.inv(s, curve."N")
      v = CA.Jacobian.add(
        CA.Jacobian.multiply(curve."G", CA.Integer.modulo(number * inv, curve."N"),
           curve."N", curve."A", curve."P"),
        CA.Jacobian.multiply(publicKey, CA.Integer.modulo(r * inv, curve."N"),
           curve."N", curve."A", curve."P" ), curve."A", curve."P")
      cond do
        r < 1 || r >= curve."N" -> false
        s < 1 || s >= curve."N" -> false
        CA.Point.isAtInfinity?(v) -> false
        CA.Integer.modulo(v.x, curve."N") != r -> false
        true -> true
      end
  end

end
