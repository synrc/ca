defmodule CA.MDoc do
  require CBOR
  @moduledoc "CA/MDOC MSO mDOC library."

  def decode(nil) do nil end
  def decode(bin) do CBOR.decode(bin) end

  def replace(s,a,b) do :re.replace(s,a,b,[:global,{:return,:binary}]) end
  def parseMDocB64(x) do {:ok, b64} = :file.read_file x ; decode(:base64.decode(b64)) end
  def parseMDocB64U(x) do {:ok, b64} = :file.read_file x ; decode(:base64.decode(replace(replace(b64,"_","/"),"-","+"))) end
  def parseMDocHex(x) do {:ok, hex} = :file.read_file x ; decode(:oid.unhex(hex)) end

  def testMDoc(x) do
      {:ok, bin} = :file.read_file x
      case :filename.extension(x) do
         '.b64' -> [bin: byte_size(:erlang.term_to_binary(:base64.decode(bin))), name: x]
         '.b64u' -> [bin: byte_size(:erlang.term_to_binary(:base64.decode(replace(replace(bin,"_","/"),"-","+")))), name: x]
         '.hex' -> [bin: byte_size(:erlang.term_to_binary(:oid.unhex(bin))), name: x]
      end
  end

  def parseDigest(map) do
      elementIdentifier = :maps.get("elementIdentifier", map, [])
      elementValue = :maps.get("elementValue", map, [])
      digestID = :maps.get("digestID", map, [])
      %CBOR.Tag{tag: :bytes, value: random} = :maps.get("random", map, %CBOR.Tag{tag: :bytes, value: ""})
      [
        elementIdentifier: elementIdentifier,
        elementValue: elementValue,
        digestID: digestID,
        random: :base64.encode(random),
      ]
  end

  def parseDocType(map) do
      dki = :maps.get("deviceKeyInfo", map, [])
      da = :maps.get("digestAlgorithm", map, [])
      docType = :maps.get("docType", map, [])
      status = :maps.get("status", map, [])
      version = :maps.get("version", map, [])
      validityInfo = :maps.get("validityInfo", map, [])
      valueDigests = :maps.get("valueDigests", map, [])
      [
        docType: docType,
        digestAlgorithm: da,
        deviceKeyInfo: dki,
        validityInfo: validityInfo,
        status: status,
        valueDigests: valueDigests,
        version: version,
      ]
  end

  def parseTag(%{1 => value}) when is_integer(value) do
      [tag: 1, value: value]
  end

  def parseTag(%{33 => %CBOR.Tag{tag: type, value: value}}) when is_binary(value) do
      {:ok, cbor, _} = decode(value)
      [tag: {33,type}, value: :base64.encode(value)]
  end

  def parseTag(%{33 => %CBOR.Tag{tag: type, value: value}}) do
      {:ok, cbor, _} = decode(value)
      [tag: {33,type}, value: cbor]
  end

  def parseTag(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes) do
      try do
        case decode(bytes) do
             {:ok, cbor, _} -> [tag: :bytes, decoded: true, value: parseTag(cbor)]
        end
      rescue _ ->
         [tag: :bytes, value: :base64.encode(bytes)]
      end
  end

  def parseTag(%CBOR.Tag{tag: :simple, value: bytes}) when is_binary(bytes) do
      [tag: :simple, value: :base64.encode(bytes)]
  end

  def parseTag(%CBOR.Tag{tag: type1, value: %CBOR.Tag{tag: type2, value: bytes}}) when is_binary(bytes) do
      {:ok, cbor, _} = decode(bytes)
      [tag: {type1, type2}, decoded: true, value: parseTag(cbor)]
  end

  def parseTag(%CBOR.Tag{tag: type, value: bytes}) when is_binary(bytes) do
      {:ok, cbor, _} = decode(bytes)
      [tag: type, decoded: true, value: parseTag(cbor)]
  end

  def parseTag(map) when is_map(map) do
      case :maps.get("docType", map, []) do
          [] -> case :maps.get("elementIdentifier", map, []) do
                  [] -> map
                  _ -> parseDigest(map)
                end
           _ -> parseDocType(map)
      end
  end

  def parseTag(value) do value end

  def parseMDoc(%{"issuerAuth"=> [f,s|issuerAuth], "nameSpaces"=> nameSpaces}) do
      [{name,nameSpacesList}] = :maps.to_list(nameSpaces)
      [
        ns: name,
        header: parseTag(f),
        certificate: parseTag(s),
        issuerAuth: :lists.map(fn x -> parseTag(x) end, issuerAuth),
        nameSpaces: :lists.map(fn x -> parseTag(x) end, nameSpacesList),
      ]
  end

  def parseMDoc(%{"documents"=>documents}) do
      :lists.map(fn x -> parseMDoc(x) end, documents)
  end

  def parseMDoc(map) do
      map
  end

  def parseMDocEnvelop(x) do 
      {:ok, bin} = :file.read_file x
      case :filename.extension(x) do
         ".b64" -> {:ok, mDoc, _} = parseMDocB64(x) ; parseMDoc(mDoc)
         ".b64u" -> {:ok, mDoc, _} = parseMDocB64U(x) ; parseMDoc(mDoc)
         ".hex" -> {:ok, mDoc, _} = parseMDocHex(x) ; parseMDoc(mDoc)
      end
  end

  def test(folder \\ "cbor") do
      :lists.map(fn x -> parseMDoc(x) end, :filelib.wildcard ['test/#{folder}/*'])
  end

end
