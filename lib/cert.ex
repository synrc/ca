defmodule CA.KEP do
  require Record

  Record.defrecord(:certAttrs, serial: "", cn: "", givenName: "", surname: "", o: "", title: "", ou: "", c: "", locality: "")

  def extract(code, person) do
    case :lists.keyfind(code, 2, person) do
      false -> ""
      {_, _, {:printable, str}} -> str
      {_, _, {:utf8, str}} -> str
    end
  end

  def parseSignData(bin) do
    {_, {:ContentInfo, _, ci}} = :KEP.decode(:ContentInfo, bin)
    {:ok, {:SignedData, _, alg, x, c, x1, x2}} = :KEP.decode(:SignedData, ci)
    parseSignDataCert({alg,x,c,x1,x2})
  end

  def parseSignDataCert({_,_,:asn1_NOVALUE,_,_}), do: []
  def parseSignDataCert({_,_,[cert],_,_}), do: parseCert(cert)

  def parseAttrs(attrs) do
    certAttrs(
      o: extract({2, 5, 4, 10}, attrs),
      ou: extract({2, 5, 4, 11}, attrs),
      title: extract({2, 5, 4, 12}, attrs),
      cn: extract({2, 5, 4, 3}, attrs),
      givenName: extract({2, 5, 4, 42}, attrs),
      surname: extract({2, 5, 4, 4}, attrs),
      locality: extract({2, 5, 4, 7}, attrs),
      serial: extract({2, 5, 4, 5}, attrs),
      c: extract({2, 5, 4, 6}, attrs)
    )
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
  def oid(x,v) when is_binary(x), do: {:oid.decode(x),pair(v,[])}
  def oid(x,v), do: {x,v}

  def flat(code,{k,v},acc) when is_integer(k), do: [flat(code,v,acc)|acc]
  def flat(code,{k,v},acc), do: [flat(code,k,acc)|acc]
  def flat(code,k,acc) when is_list(k), do: [:lists.map(fn x -> flat(code,x,acc) end, k)|acc]
  def flat(code,k,acc) when is_binary(k), do: [k|acc]

  def parseCert(cert) do
    {:Certificate, a, _, _} = cert
    {:Certificate_toBeSigned, _ver, _sel, _alg, issuer, _val, issuee, _, _, _, exts} = a
    extensions = :lists.map(fn {:Extension,code,_,b} ->
         oid(code, :lists.flatten(flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
    person = :lists.flatten(:erlang.element(2, issuee))
    ca = :lists.flatten(:erlang.element(2, issuer))
    {parseAttrs(person),parseAttrs(ca),extensions}
  end
end
