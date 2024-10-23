defmodule CA.CAdES do
  @moduledoc "CAdES (804) Qualified Digital Signature library."
  require Record
  Record.defrecord(:certinfo, serial: "", cn: "", givenName: "", surname: "", timeStamp: "",
                              attrs: [], o: "", title: "", ou: "", c: "", locality: "")

  def subj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn
            [{t,oid,{:uTF8String,x}}] ->
                [{t,oid,:asn1rt_nif.encode_ber_tlv({12, :erlang.iolist_to_binary(x)})}]
            [{t,oid,x}] when is_list(x) ->
                [{t,oid,:asn1rt_nif.encode_ber_tlv({19, :erlang.iolist_to_binary(x)})}]
            [{t,oid,x}] -> [{t,oid,x}] end, attrs)}
  end

  def unsubj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn [{t,oid,x}] ->
             case :asn1rt_nif.decode_ber_tlv(x) do
                  {{12,a},_} -> [{t,oid,{:uTF8String,a}}]
                  {{19,a},_} -> [{t,oid,:erlang.binary_to_list(a)}]
             end end, attrs)}
  end

  def readSignature(name \\ "2.p7s") do
      {:ok, bin} = :file.read_file name
      ber = parseSignData(bin)
      ber
  end

  def extract(code, person) do
      case :lists.keyfind(code, 2, person) do
           false -> ""
           {_, _, {:printable, str}} -> str
           {_, _, {:utf8, str}} -> str
      end
  end

  def parseSignData(bin) do
      {_, {:ContentInfo, oid, ci}} = :KEP.decode(:ContentInfo, bin)
      {:ok, {:SignedData, _, alg, x, c, x1, si}} = :KEP.decode(:SignedData, ci)
      parseSignDataCert({alg,oid,x,c,x1,si})
  end

  def parseSignDataCert({_,_,_,:asn1_NOVALUE,_,_}), do: []
  def parseSignDataCert({_,_,_,[cert],_,attr}), do: parseCert(cert,attr)

  def parseAttrs(attrs, options) do
      certinfo(
        o: extract({2, 5, 4, 10}, attrs),
        ou: extract({2, 5, 4, 11}, attrs),
        title: extract({2, 5, 4, 12}, attrs),
        cn: extract({2, 5, 4, 3}, attrs),
        timeStamp: extract({2, 5, 4, 3}, attrs),
        givenName: extract({2, 5, 4, 42}, attrs),
        surname: extract({2, 5, 4, 4}, attrs),
        locality: extract({2, 5, 4, 7}, attrs),
        serial: extract({2, 5, 4, 5}, attrs),
        c: extract({2, 5, 4, 6}, attrs),
        attrs: options)
  end

  def pair([],acc), do: acc
  def pair([x],acc), do: [x|acc]
  def pair([a,b|t],acc), do: pair(t,[{hd(mapOids([:oid.decode(a)])),b}|acc])

  def mapOidsDecode(list) do
      :lists.map(fn x ->
         :erlang.iolist_to_binary(:string.join(:lists.map(fn y -> :erlang.integer_to_list(y) end,
         :erlang.tuple_to_list(:oid.decode(x))),'.')) end, list)
  end

  def mapOids(list) do
      :lists.map(fn x ->
         :erlang.iolist_to_binary(:string.join(:lists.map(fn y -> :erlang.integer_to_list(y) end,
         :erlang.tuple_to_list(x)),'.')) end, list)
  end

  def oid({1,3,6,1,5,5,7,1,1}, v), do: {:authorityInfoAccess, pair(v,[])}
  def oid({1,3,6,1,5,5,7,1,3}, [v1,v2,url,_lang,v3,v4,v5]), do: {:qcStatements, {url, mapOidsDecode([v1,v2,v3,v4,v5])}}
  def oid({1,3,6,1,5,5,7,1,11},v), do: {:subjectInfoAccess, pair(v,[])}
  def oid({2,5,29,9},v),  do: {:subjectDirectoryAttributes, pair(v,[])}
  def oid({2,5,29,14},v), do: {:subjectKeyIdentifier, :base64.encode(hd(pair(v,[])))}
  def oid({2,5,29,15},v), do: {:keyUsage, pair(v,[])}
  def oid({2,5,29,16},v), do: {:privateKeyUsagePeriod, v}
  def oid({2,5,29,17},v), do: {:subjectAltName, pair(v,[])}
  def oid({2,5,29,19},v), do: {:basicConstraints, pair(v,[])}
  def oid({2,5,29,31},v), do: {:cRLDistributionPoints, pair(v,[])}
  def oid({2,5,29,32},[v1,v2,url]), do: {:certificatePolicies, {url, mapOidsDecode([v1,v2])}}
  def oid({2,5,29,35},v), do: {:authorityKeyIdentifier, :base64.encode(hd(pair(v,[])))}
  def oid({2,5,29,46},v), do: {:freshestCRL, pair(v,[])}
  def oid({1,2,840,113549,1,9,3},v), do: {:contentType, hd(mapOidsDecode([v]))}
  def oid({1,2,840,113549,1,9,4},v), do: {:messageDigest, :base64.encode(:erlang.element(2,:KEP.decode(:MessageDigest, v)))}
  def oid({1,2,840,113549,1,9,5},v), do: {:signingTime, :erlang.element(2,:erlang.element(1,:asn1rt_nif.decode_ber_tlv(v)))}
  def oid({1,2,840,113549,1,9,16,2,47},v) do
      {:SigningCertificateV2,[{:ESSCertIDv2, _, _, {_,_,serial}}],_} = :erlang.element(2,:KEP.decode(:SigningCertificateV2, v))
      {:signingCertificateV2, serial}
  end
  def oid({1,2,840,113549,1,9,16,2,20},v) do
      {:ContentInfo, oid, value} = :erlang.element(2,:KEP.decode(:ContentInfo,v))
      {:ok, {:SignedData, _, _alg, {_,_,x}, _c, _x1, _si}} = :KEP.decode(:SignedData, value)
      {:ok, {:TSTInfo, _vsn, _oid, {:MessageImprint, _, x}, serial, ts, _,_,_,_}} = :KEP.decode(:TSTInfo, x)
      {:contentTimestamp, {hd(mapOids([oid])), serial, :erlang.iolist_to_binary(ts), :base64.encode(x)}}
  end
  def oid(x,v) when is_binary(x), do: {:oid.decode(x),pair(v,[])}
  def oid(x,v), do: {x,v}

  def flat(code,{k,v},acc) when is_integer(k), do: [flat(code,v,acc)|acc]
  def flat(code,{k,_v},acc), do: [flat(code,k,acc)|acc]
  def flat(code,k,acc) when is_list(k), do: [:lists.map(fn x -> flat(code,x,acc) end, k)|acc]
  def flat(_code,k,acc) when is_binary(k), do: [k|acc]

  def parseCert(cert, [si|_]) do
    {:SignerInfo, _v, _serial, _alg, attrs, _, _, _} = si
    {:Certificate, a, _, _} = cert
    {:Certificate_toBeSigned, _ver, _sel, _alg, issuer, _val, issuee, _a, _b, _c, exts} = a
    extensions = :lists.map(fn {:Extension,code,_x,b} ->
         oid(code, :lists.flatten(flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
    attributes = :lists.map(fn {:Attribute,code,[{_,v}],_} ->
         oid(code, v)
      end, attrs)
    person = :lists.flatten(:erlang.element(2, issuee))
    ca = :lists.flatten(:erlang.element(2, issuer))
    [parseAttrs(person,extensions),parseAttrs(ca,attributes)]
  end

  def parseCert(cert) do
    {:Certificate, a, _, _} = cert
    {:Certificate_toBeSigned, _ver, _sel, _alg, issuer, _val, issuee, _a, _b, _c, exts} = a
    extensions = :lists.map(fn {:Extension,code,_x,b} ->
         oid(code, :lists.flatten(flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
    person = :lists.flatten(:erlang.element(2, issuee))
    ca = :lists.flatten(:erlang.element(2, issuer))
    [parseAttrs(person,extensions),parseAttrs(ca,[])]
  end

end
