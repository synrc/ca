defmodule CA.KDF do
  @moduledoc "CA/KDF library."

  def hs(16), do: :md5
  def hs(20), do: :sha
  def hs(28), do: :sha224
  def hs(32), do: :sha256
  def hs(48), do: :sha384
  def hs(64), do: :sha512

  def hl(:md5),    do: 16
  def hl(:sha),    do: 20
  def hl(:sha224), do: 28
  def hl(:sha256), do: 32
  def hl(:sha384), do: 48
  def hl(:sha512), do: 64

  def derive({_,h}, d, len, x) do
      :binary.part(:lists.foldr(fn i, a ->
          :crypto.hash(h, d <> <<i::32>> <> x) <> a
      end, <<>>, :lists.seq(1,round(Float.ceil(len/hl(h))))), 0, len)
  end

end
