defmodule CA.CAdES do
  @moduledoc "CAdES (804) Qualified Digital Signature library ."
  require Record
  Record.defrecord(:certAttrs, serial: "", cn: "", givenName: "", surname: "",
                               timeStamp: "",
                               o: "", title: "", ou: "", c: "", locality: "")

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

  def readSignature() do
      name = "signature001.p7s"
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
      {_, {:ContentInfo, x, ci}} = :KEP.decode(:ContentInfo, bin)
      {:ok, {:SignedData, _, alg, x, c, x1, si}} = :KEP.decode(:SignedData, ci)
      parseSignDataCert({alg,x,c,x1,si})
  end

  def parseSignDataCert({_,_,:asn1_NOVALUE,_,_}), do: []
  def parseSignDataCert({_,_,[cert],_,attr}), do: parseCert(cert,attr)

  def parseAttrs(attrs) do
      :io.format 'Attr: ~p~n', [attrs]
      certAttrs(
        o: extract({2, 5, 4, 10}, attrs),
        ou: extract({2, 5, 4, 11}, attrs),
        title: extract({2, 5, 4, 12}, attrs),
        cn: extract({2, 5, 4, 3}, attrs),
        timeStamp: extract({2, 5, 4, 3}, attrs),
        givenName: extract({2, 5, 4, 42}, attrs),
        surname: extract({2, 5, 4, 4}, attrs),
        locality: extract({2, 5, 4, 7}, attrs),
        serial: extract({2, 5, 4, 5}, attrs),
        c: extract({2, 5, 4, 6}, attrs))
  end

  def pair([],acc), do: acc
  def pair([x],acc), do: [x|acc]
  def pair([a,b|t],acc), do: pair(t,[{:oid.decode(a),b}|acc])

  def oid({1,3,6,1,5,5,7,1,1}, v), do: {:authorityInfoAccess, pair(v,[])}
  def oid({1,3,6,1,5,5,7,1,3}, [v]), do: {:qcStatements, :oid.decode v}
  def oid({1,3,6,1,5,5,7,1,11},v), do: {:subjectInfoAccess, pair(v,[])}
  def oid({2,5,29,9},v),  do: {:subjectDirectoryAttributes, pair(v,[])}
  def oid({2,5,29,14},v), do: {:subjectKeyIdentifier, pair(v,[])}
  def oid({2,5,29,15},v), do: {:keyUsage, pair(v,[])}
  def oid({2,5,29,16},v), do: {:privateKeyUsagePeriod, v}
  def oid({2,5,29,17},v), do: {:subjectAltName, pair(v,[])}
  def oid({2,5,29,19},v), do: {:basicConstraints, pair(v,[])}
  def oid({2,5,29,31},v), do: {:cRLDistributionPoints, pair(v,[])}
  def oid({2,5,29,32},[v]), do: {:certificatePolicies, :oid.decode v}
  def oid({2,5,29,35},v), do: {:authorityKeyIdentifier, pair(v,[])}
  def oid({2,5,29,46},v), do: {:freshestCRL, pair(v,[])}
  def oid({2,5,29,46},v), do: {:freshestCRL, pair(v,[])}
  def oid({1,2,840,113549,1,9,3},v), do: {:contentType, :oid.decode(v)}
  def oid({1,2,840,113549,1,9,4},v), do: {:messageDigest, :asn1rt_nif.decode_ber_tlv v}
  def oid({1,2,840,113549,1,9,5},v), do: {:signingTime, :asn1rt_nif.decode_ber_tlv(v)}
  def oid({1,2,840,113549,1,9,16,2,47},v), do: {:signingCertificateV2, :erlang.element(2,:KEP.decode(:AttributeValue, v))}
  def oid({1,2,840,113549,1,9,16,2,20},v), do: {:contentTimestamp, :erlang.element(2,:KEP.decode(:AttributeValue, v)) }
  def oid(x,v) when is_binary(x), do: {:oid.decode(x),pair(v,[])}
  def oid(x,v), do: {x,v}

  def flat(code,{k,v},acc) when is_integer(k), do: [flat(code,v,acc)|acc]
  def flat(code,{k,_v},acc), do: [flat(code,k,acc)|acc]
  def flat(code,k,acc) when is_list(k), do: [:lists.map(fn x -> flat(code,x,acc) end, k)|acc]
  def flat(_code,k,acc) when is_binary(k), do: [k|acc]

  def parseCert(cert, [si|_]) do
    :io.format '1 ~p ~n',[:erlang.element(1,si)]
    :io.format '2 ~p ~n',[:erlang.element(2,si)]
    :io.format '3 ~p ~n',[:erlang.element(3,si)]
    :io.format '4 ~p ~n',[:erlang.element(4,si)]
    :io.format '5 ~p ~n',[:erlang.element(5,si)]
    :io.format '6 ~p ~n',[:erlang.element(6,si)]
    :io.format '7 ~p ~n',[:erlang.element(7,si)]
    :io.format '8 ~p ~n',[:erlang.element(8,si)]
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
    {parseAttrs(person),parseAttrs(ca),extensions,attributes}
  end

end
