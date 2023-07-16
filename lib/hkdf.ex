defmodule HKDF do

  def hl(:sha),    do: 20
  def hl(:sha224), do: 28
  def hl(:sha256), do: 32
  def hl(:sha384), do: 48
  def hl(:sha512), do: 64

  def derive({_, h}, d, len, x) do
      :binary.part(:lists.foldr(fn i, a ->
          :crypto.hash(h, d <> <<i::32>> <> x) <> a
      end, <<>>, :lists.seq(1,round(Float.ceil(len/hl(h))))), 0, len)
  end

end
