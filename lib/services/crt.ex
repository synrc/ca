defmodule CA.CRT do
  @moduledoc "X.509 Certificates."

  def subj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn
            [{t,oid,{:uTF8String,x}}] ->
                [{t,oid,:asn1rt_nif.encode_ber_tlv({12, :erlang.iolist_to_binary(x)})}]
            [{t,oid,x}] when is_list(x) ->
                [{t,oid,:asn1rt_nif.encode_ber_tlv({19, :erlang.iolist_to_binary(x)})}]
            [{t,oid,x}] -> [{t,oid,x}] end, attrs)}
  end

  def unsubj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.flatmap(fn [{t,oid,x}] when is_binary(x) ->
             case :asn1rt_nif.decode_ber_tlv(x) do
                  {{12,a},_} -> [{t,oid,{:uTF8String,a}}]
                  {{19,a},_} -> [{t,oid,:erlang.binary_to_list(a)}]
             end 
             _ -> [] end, attrs)}
  end

  def readSignature(name \\ "2.p7s") do
      {:ok, bin} = :file.read_file name
      ber = CA.CMS.parseSignData(bin)
      ber
  end

  def extract(code, person) do
      case :lists.keyfind(code, 2, person) do
           false -> []
           {_, _, <<19,_,bin::binary>>} -> bin
           {_, _, {:printable, str}} -> str
           {_, _, {:utf8, str}} -> str
      end
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
  def oid({1,3,6,1,4,1,11129,2,4,2}, v), do: {:signedCertificateTimestamp, :base64.encode(hd(pair(v,[])))}
  def oid({1,3,6,1,5,5,7,1,11},v), do: {:subjectInfoAccess, pair(v,[])}
  def oid({1,3,6,1,5,5,7,1,3}, v), do: {:qcStatements, mapOidsDecode(v)}
  def oid({2,5,29,9},v),  do: {:subjectDirectoryAttributes, pair(v,[])}
  def oid({2,5,29,14},v), do: {:subjectKeyIdentifier, :base64.encode(hd(pair(v,[])))}
  def oid({2,5,29,15},[v]), do: {:keyUsage, CA.EST.decodeKeyUsage(<<3,2,v::binary>>) }
  def oid({2,5,29,16},v), do: {:privateKeyUsagePeriod, v}
  def oid({2,5,29,17},v), do: {:subjectAltName, :lists.map(fn x ->
                                 case CA.ALG.lookup(:oid.decode(x)) do
                                      false -> x
                                      {alg,_} -> alg
                                 end end, v)}
  def oid({2,5,29,37},v), do: {:extKeyUsage, mapOids(:lists.map(fn x -> :oid.decode(x) end, v)) }
  def oid({2,5,29,19},v), do: {:basicConstraints, v}
  def oid({2,5,29,31},v), do: {:cRLDistributionPoints, pair(v,[])}
  def oid({2,5,29,32},v), do: {:certificatePolicies, mapOids(:lists.map(fn x -> :oid.decode(x) end, v))}
  def oid({2,5,29,35},v), do: {:authorityKeyIdentifier, :base64.encode(hd(pair(v,[])))}
  def oid({2,5,29,46},v), do: {:freshestCRL, pair(v,[])}
  def oid({2,5,29,97},v), do: {:unknown97, v}
  def oid({1,2,840,113549,1,9,3},v), do: {:contentType, hd(mapOidsDecode([v]))}
  def oid({1,2,840,113549,1,9,4},v), do: {:messageDigest, :base64.encode(:erlang.element(2,:KEP.decode(:MessageDigest, v)))}
  def oid({1,2,840,113549,1,9,5},v), do: {:signingTime, :erlang.element(2,:erlang.element(1,:asn1rt_nif.decode_ber_tlv(v)))}

  def oid({1, 2, 840, 113549, 1, 9, 16, 2}, v) do {:"id-aa", v} end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 14}, v) do {:"id-aa-timeStampToken", v}
      {:ok, {:ContentInfo, oid, value}} = :KEP.decode(:ContentInfo,v)
      {:ok, {:SignedData, _, _alg, {_,_,x}, _c, _x1, _si}} = :KEP.decode(:SignedData, value)
      {:ok, {:TSTInfo, _vsn, _oid, {:MessageImprint, _, x}, serial, ts, _,_,_,_}} = :KEP.decode(:TSTInfo, x)
      {:timeStampToken, {hd(mapOids([oid])), serial, :erlang.iolist_to_binary(ts), :base64.encode(x)}}
      end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 18}, v) do {:"id-aa-ets-signerAttr", v} end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 19}, v) do {:"id-aa-ets-otherSigCert", v} end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 20}, v) do
      {:ok, {:ContentInfo, oid, value}} = :KEP.decode(:ContentInfo,v)
      {:ok, {:SignedData, _, _alg, {_,_,x}, _c, _x1, _si}} = :KEP.decode(:SignedData, value)
      {:ok, {:TSTInfo, _vsn, _oid, {:MessageImprint, _, x}, serial, ts, _,_,_,_}} = :KEP.decode(:TSTInfo, x)
      {:contentTimestamp, {hd(mapOids([oid])), serial, :erlang.iolist_to_binary(ts), :base64.encode(x)}}
  end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 22}, v) do
      {:ok, x} = :KEP.decode(:CompleteRevocationRefs, v)
      {:revocationRefs, x}
  end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 21}, v) do
#      {:ok, certList} = :KEP.decode(:CertificateList, v)
      {:certificateRefs, v}
  end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 23}, v) do
      {:ok, certList} = :KEP.decode(:Certificates, v)
      list = :lists.map(fn cert -> CA.CRT.parseCert(cert) end, certList)
      {:certificateValues, list}
  end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 24}, v) do
      {:ok, {:RevocationValues, :asn1_NOVALUE, ocspVals, :asn1_NOVALUE}} = :KEP.decode(:RevocationValues, v)
      {:ok, list} = :KEP.decode(:BasicOCSPResponses, ocspVals)
      list = :lists.map(fn {:BasicOCSPResponse,{:ResponseData,_ver,{_,rdn},_time,_responses,_ext},_alg,_bin,_} -> CA.CRT.rdn(rdn) end, list)
      {:revocationValues, list}
  end

  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 47}, v) do
      {:ok, {:SigningCertificateV2,[{:ESSCertIDv2, _, _, {_,_,serial}}],_}} = :KEP.decode(:SigningCertificateV2, v)
      {:signingCertificateV2, serial}
  end

  def oid(x,v) when is_binary(x), do: {:oid.decode(x),pair(v,[])}
  def oid(x,v), do: {x,v}

  def flat(code,{k,v},acc) when is_integer(k), do: [flat(code,v,acc)|acc]
  def flat(code,{k,_v},acc), do: [flat(code,k,acc)|acc]
  def flat(code,k,acc) when is_list(k), do: [:lists.map(fn x -> flat(code,x,acc) end, k)|acc]
  def flat(_code,k,acc) when is_binary(k), do: [k|acc]

  def rdn({2, 5, 4, 3}),  do: "cn" # commonName
  def rdn({2, 5, 4, 4}),  do: "sn" # sureName
  def rdn({2, 5, 4, 5}),  do: "serialNumber"
  def rdn({2, 5, 4, 6}),  do: "c" # country
  def rdn({2, 5, 4, 7}),  do: "l" # localityName
  def rdn({0,9,2342,19200300,100,1,25}),  do: "dc"
  def rdn({2, 5, 4, 10}), do: "o" # organization
  def rdn({2, 5, 4, 11}), do: "ou" # organizationalUnit
  def rdn({2, 5, 4, 12}), do: "title"
  def rdn({2, 5, 4, 13}), do: "description"
  def rdn({2, 5, 4, 14}), do: "device"
  def rdn({2, 5, 4, 15}), do: "businessCategory"
  def rdn({2, 5, 4, 42}), do: "givenName"
  def rdn({2, 5, 4, 97}), do: "organizationIdentifier"
  def rdn({2, 5, 6, 3}),  do: "locality"
  def rdn({2, 5, 6, 4}),  do: "organization"
  def rdn({2, 5, 6, 5}),  do: "organizationalUnit"
  def rdn({2, 5, 6, 6}),  do: "person"
  def rdn({2, 5, 6, 7}),  do: "organizationalPerson"
  def rdn({2, 5, 6, 8}),  do: "organizationalRole"
  def rdn({2, 5, 6, 9}),  do: "groupOfNames"
  def rdn({:rdnSequence, list}) do
      :lists.map(fn [{_,oid,{_,list}}] -> {rdn(oid),"#{list}"}
                     {_,oid,{_,list}}  -> {rdn(oid),"#{list}"}
                     {_,oid,list}      -> {rdn(oid),"#{list}"} end, list)
  end

  def rdn2({:rdnSequence, list}) do
      Enum.join :lists.map(fn [{_,oid,{_,list}}] -> "#{rdn(oid)}=#{list}"
                              {_,oid,{_,list}} -> "#{rdn(oid)}=#{list}"
                              {_,oid,list} -> "#{rdn(oid)}=#{list}" end, list), "/"
  end

  def decodePointFromPublic(oid0,oid,publicKey) do
      bin = :binary.part(publicKey,1,:erlang.size(publicKey)-1)
      curve = CA.KnownCurves.getCurveByOid(oid)
      baseLength = CA.Curve.getLength(curve)
      xs = :binary.part(bin, 0, baseLength)
      ys = :binary.part(bin, baseLength, :erlang.size(bin) - baseLength)
      [ scheme: :erlang.element(1,CA.ALG.lookup(oid0)),
        curve: :erlang.element(1,CA.ALG.lookup(oid)),
        x: CA.ECDSA.numberFromString(xs),
        y: CA.ECDSA.numberFromString(ys)
      ]
  end

  def decodePublicKey(oid,oid2,publicKey) do
      :io.format '~p~n', [oid]
      case oid do
           {1,2,804,2,1,1,1,1,3,1,1} -> :base64.encode publicKey 
           _ -> decodePointFromPublic(oid, CA.EST.decodeObjectIdentifier(oid2),publicKey)
      end
  end

  def parseCert(cert, _) do parseCert(cert) end
  def parseCert(cert) do
      {:Certificate, tbs, _, _} = cert
      {_, ver, serial, {_,alg,_}, issuer, {_,{_,nb},{_,na}}, issuee,
         {:SubjectPublicKeyInfo, {_, oid, oid2}, publicKey}, _b, _c, exts} = tbs
      extensions = :lists.map(fn {:Extension,code,_x,b} ->
         oid(code, :lists.flatten(flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
      [ resourceType: :Certificate,
        version: ver,
        signatureAlgorithm: :erlang.element(1,CA.ALG.lookup(alg)),
        subject: rdn(unsubj(issuee)),
        issuer:  rdn(unsubj(issuer)),
        serial: :base64.encode(CA.EST.integer(serial)),
        validity: [from: nb, to: na],
        publicKey: decodePublicKey(oid, oid2, publicKey),
        extensions: extensions
      ]
  end

  def parseCertFile(file) do
      {:ok, bin} = :file.read_file file
      {:ok, cert} = :"AuthenticationFramework".decode :Certificate, bin
      parseCert(cert)
  end

end
