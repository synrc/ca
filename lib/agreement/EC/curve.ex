defmodule CA.Curve do
  require CA.Integer
  require CA.Point
  defstruct [:A, :B, :P, :N, :G, :name, :oid]

  # ANSI X9.142–2020 ECDSA http://oid-info.com/get/1.3.132.0

  def oid(:sect163k1), do: {1,3,132,0,1}
  def oid(:sect163r2), do: {1,3,132,0,15}
  def oid(:secp224r1), do: {1,3,132,0,33}
  def oid(:sect233k1), do: {1,3,132,0,26}
  def oid(:sect233r1), do: {1,3,132,0,27}
  def oid(:sect283k1), do: {1,3,132,0,16}
  def oid(:sect283r1), do: {1,3,132,0,17}
  def oid(:secp384r1), do: {1,3,132,0,34}
  def oid(:sect409k1), do: {1,3,132,0,36}
  def oid(:sect409r1), do: {1,3,132,0,37}
  def oid(:secp521r1), do: {1,3,132,0,35}
  def oid(:sect571k1), do: {1,3,132,0,38}
  def oid(:sect571r1), do: {1,3,132,0,39}

  def contains?(curve, p) do
      cond do
        p.x < 0 || p.x > curve."P" - 1 -> false
        p.y < 0 || p.y > curve."P" - 1 -> false
        CA.Integer.ipow(p.y, 2) - (CA.Integer.ipow(p.x, 3) + curve."A" * p.x + curve."B")
          |> CA.Integer.modulo(curve."P") != 0 -> false
        true -> true
      end
  end
  def getLength(curve) do
      div(1 + String.length(Integer.to_string(curve."N", 16)), 2)
  end
end
