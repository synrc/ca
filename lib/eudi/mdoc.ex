defmodule CA.MDoc do
  require CBOR
  @moduledoc "CA/MDOC MSO mDOC library."

  def replace(s,a,b) do :re.replace(s,a,b,[:global,{:return,:binary}]) end
  def parseMDocB64(x) do
      {:ok, b64} = :file.read_file x
      CBOR.decode(:base64.decode(b64))
  end
  def parseMDocB64U(x) do
      {:ok, b64} = :file.read_file x
      CBOR.decode(:base64.decode(replace(replace(b64,"_","/"),"-","+")))
  end
  def parseMDocHex(x) do
      {:ok, hex} = :file.read_file x
      CBOR.decode(:oid.unhex(hex))
  end
  def parseMDoc(x) do 
      {:ok, bin} = :file.read_file x
      case :filename.extension(x) do
         '.b64' -> [base64: byte_size(:erlang.term_to_binary(:base64.decode(bin))), name: x]
         '.b64u' -> [base64: byte_size(:erlang.term_to_binary(:base64.decode(replace(replace(bin,"_","/"),"-","+")))), name: x]
         '.hex' -> [hex: byte_size(:erlang.term_to_binary(:oid.unhex(bin))), name: x]
      end
  end

  def test(folder \\ "cbor") do
      :lists.map(fn x -> parseMDoc(x) end, :filelib.wildcard ['test/#{folder}/*'])
  end

end
