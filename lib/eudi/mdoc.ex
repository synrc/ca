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
      x = :erlang.iolist_to_binary(x)
      {:ok, bin} = :file.read_file x
      case :filename.extension(x) do
         ".b64" -> [bin: byte_size(:erlang.term_to_binary(:base64.decode(bin))), name: x]
         ".b64u" -> [bin: byte_size(:erlang.term_to_binary(:base64.decode(replace(replace(bin,"_","/"),"-","+")))), name: x]
         ".hex" -> [bin: byte_size(:erlang.term_to_binary(:oid.unhex(bin))), name: x]
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
      digests = case :maps.to_list(valueDigests) do
          x when is_list(x) -> :lists.map(fn a -> :lists.map(fn {_,b} -> parseTag(b) end, :maps.to_list(a)) end, x)
          x -> x
      end
      [
        docType: docType,
        digestAlgorithm: da,
        deviceKeyInfo: dki,
        validityInfo: validityInfo,
        status: status,
        valueDigests: digests,
        version: version,
      ]
  end

  def parseTag(%{1 => value}) when is_integer(value) do
      [tag: 1, value: value]
  end

  def parseTag(%{33 => %CBOR.Tag{tag: type, value: value}}) when is_binary(value) do
      [tag: {33,type}, value: :base64.encode(value)]
  end

  def parseTag(%{33 => tags}) when is_list(tags) do
      :lists.map(fn %CBOR.Tag{tag: type, value: value} ->
        [tag: {33,type}, value: :base64.encode(value)]
      end, tags)
  end

  def parseTag(%{33 => %CBOR.Tag{tag: type, value: value}}) do
      [tag: {33,type}, value: :base64.encode(value)]
  end

  def parseTag(%CBOR.Tag{tag: :bytes, value: bytes}) when is_binary(bytes) do
      try do
        case decode(bytes) do
             {:ok, cbor, _} -> [tag: :bytes, decoded: true, value: parseTag(cbor)]
        end
      rescue _ ->
         [tag: :bytes, value: :base64.encode(bytes), raw: true]
      end
  end

  def parseTag(%CBOR.Tag{tag: :simple, value: bytes}) when is_binary(bytes) do
      {:ok, cbor, _} = decode(bytes)
      [tag: :simple, value: :base64.encode(bytes)]
  end

  def parseTag(%CBOR.Tag{tag: type1, value: %CBOR.Tag{tag: type2, value: bytes}}) when is_binary(bytes) do
      {:ok, cbor, _} = decode(bytes)
      [tag: {type1, type2}, decoded: true, value: parseMapValue(cbor)]
  end

  def parseTag(%CBOR.Tag{tag: type, value: bytes}) when is_binary(bytes) do
      {:ok, cbor, _} = decode(bytes)
      [tag: type, decoded: true, value: cbor]
  end

  def parseTag(value) when is_binary(value) do :base64.encode(value) end

  def parseTag(value) do value end

  def parseMapValue(map) when is_map(map) do
      case :maps.get("elementIdentifier", map, []) do
           [] -> case :maps.get("deviceKeyInfo", map, []) do
                      [] -> map
                      _ -> parseDocType(map)
                 end
            _ -> parseDigest(map)
      end
 end

  def parseMDoc(%{"deviceAuth"=> %{"deviceSignature" => tags}, "nameSpaces"=> ns}) do
      [
        deviceAuth: [deviceSignature: :lists.map(fn x -> parseTag(x) end, tags)],
        nameSpaces: :lists.map(fn x -> parseTag(x) end, :lists.flatten([ns])),
      ]
  end

  def parseMDoc(%{"issuerAuth"=> [f,s|issuerAuth], "nameSpaces"=> nameSpaces}) do
      [{name,ns}] = :maps.to_list(nameSpaces)
      [
        header: parseTag(f),
        certificates: parseTag(s),
        issuerAuth: :lists.map(fn x -> parseTag(x) end, issuerAuth),
        nameSpaces: :lists.map(fn x -> parseTag(x) end, :lists.flatten([ns])),
        docType: name,
      ]
  end

  def parseMDoc(%{"issuerSigned"=> issuerSigned, "deviceSigned"=> deviceSigned, "docType" => docType}) do
      [
        issuerSigned: parseMDoc(issuerSigned),
        deviceSigned: parseMDoc(deviceSigned),
        docType: docType
      ]
  end

  def parseMDoc(%{"documents" => documents}) do
      :lists.map(fn x -> parseMDoc(x) end, documents)
  end

  def parseMDoc(map) do
      map
  end

  def parseMDocEnvelop(x) do 
      x = :erlang.iolist_to_binary(x)
      {:ok, bin} = :file.read_file x
      case :filename.extension(x) do
         ".b64"  -> {:ok, mDoc, _} = parseMDocB64(x)  ; parseMDoc(mDoc)
         ".b64u" -> {:ok, mDoc, _} = parseMDocB64U(x) ; parseMDoc(mDoc)
         ".hex"  -> {:ok, mDoc, _} = parseMDocHex(x)  ; parseMDoc(mDoc)
         ".hexbin"  -> {:ok, mDoc, _} = CBOR.decode(:oid.unhex(bin))  ; mDoc
      end
  end

  def test(folder \\ "mdoc") do
      :lists.map(fn x -> testMDoc(x) end, :filelib.wildcard ['test/#{folder}/*'])
  end

end
