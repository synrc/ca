defmodule CA.ECDSA do
  require CA.Point
  require CA.Integer
  require CA.Jacobian
  @moduledoc "CA/ECDSA ECC Signature (SYNRC)."

  def sign(message, privateKey, options) do
      %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})
      number = :crypto.hash(hashfunc, message) |> numberFromString()
      curve = CA.KnownCurves.secp384r1()
      randNum = CA.Integer.between(1, curve."N" - 1)
      r = CA.Jacobian.multiply(curve."G", randNum, curve."N", curve."A", curve."P").x
        |> CA.Integer.modulo(curve."N")
      s = ((number + r * privateKey) * CA.Jacobian.inv(randNum, curve."N"))
        |> CA.Integer.modulo(curve."N")
      {r, s}
  end

  def private(bin), do: numberFromString(:erlang.element(3,:erlang.element(2,X509.PrivateKey.from_pem(bin))))
  def public(bin),  do: :public_key.pem_entry_decode(hd(:public_key.pem_decode(bin)))

  def numberFromString(string) do
      Base.encode16(string)
      |> Integer.parse(16)
      |> (fn {parsedInt, ""} -> parsedInt end).()
  end

  def decodePointFromECPoint(ec) do
      {{:ECPoint, point}, {:namedCurve, oid}} = ec
      bin = :binary.part(point,1,:erlang.size(point)-1)
      curve = CA.KnownCurves.getCurveByOid(oid)
      baseLength = CA.Curve.getLength(curve)
      xs = :binary.part(bin, 0, baseLength)
      ys = :binary.part(bin, baseLength, :erlang.size(bin) - baseLength)
      %CA.Point{ x: numberFromString(xs), y: numberFromString(ys)}
  end

  def signature(name) do
      {:ok, sig} = :file.read_file name
      {:ok, {:"ECDSA-Sig-Value",r,s}}  =:"PKIXAlgs-2009".decode(:"ECDSA-Sig-Value", sig)
      {r, s}
  end

  def sign(file, key) do
      {:ok, msg} = :file.read_file file
      {:ok, pem} = :file.read_file key
      sign(msg, private(pem), [])
  end

  def verify(file, signature_file, pub) do
      {:ok, msg} = :file.read_file file
      {:ok, pem} = :file.read_file pub
      verify(msg, signature(signature_file), decodePointFromECPoint(public(pem)), [])
  end

  def verify(message, {r,s}, publicKey, options) do
      %{hashfunc: hashfunc} = Enum.into(options, %{hashfunc: :sha256})
      number = :crypto.hash(hashfunc, message) |> numberFromString()
      curve = CA.KnownCurves.secp384r1()
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
