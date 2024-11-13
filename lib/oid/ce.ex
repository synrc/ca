defmodule CA.CE do
  @moduledoc "CA Certificate Extensions OIDs."

  # https://zakon.rada.gov.ua/laws/show/z1398-12

  def oid(:"id-ce-subjectDirectoryAttributes"),   do: {2, 5, 29, 9}
  def oid(:"id-ce-subjectKeyIdentifier"),         do: {2, 5, 29, 14}
  def oid(:"id-ce-keyUsage"),                     do: {2, 5, 29, 15}
  def oid(:"id-ce-privateKeyUsagePeriod"),        do: {2, 5, 29, 16}
  def oid(:"id-ce-subjectAltName"),               do: {2, 5, 29, 17}
  def oid(:"id-ce-issuerAltName"),                do: {2, 5, 29, 18}
  def oid(:"id-ce-basicConstraints"),             do: {2, 5, 29, 19}
  def oid(:"id-ce-cRLNumber"),                    do: {2, 5, 29, 20}
  def oid(:"id-ce-reasonCode"),                   do: {2, 5, 29, 21}
  def oid(:"id-ce-expirationDate"),               do: {2, 5, 29, 22}
  def oid(:"id-ce-holdInstructionCode"),          do: {2, 5, 29, 23}
  def oid(:"id-ce-invalidityDate"),               do: {2, 5, 29, 24}
  def oid(:"id-ce-deltaCRLIndicator"),            do: {2, 5, 29, 27}
  def oid(:"id-ce-issuingDistributionPoint"),     do: {2, 5, 29, 28}
  def oid(:"id-ce-certificateIssuer"),            do: {2, 5, 29, 29}
  def oid(:"id-ce-nameConstraints"),              do: {2, 5, 29, 30}
  def oid(:"id-ce-cRLDistributionPoints"),        do: {2, 5, 29, 31}
  def oid(:"id-ce-certificatePolicies"),          do: {2, 5, 29, 32}
  def oid(:"id-ce-policyMappings"),               do: {2, 5, 29, 33}
  def oid(:"id-ce-authorityKeyIdentifier"),       do: {2, 5, 29, 35}
  def oid(:"id-ce-policyConstraints"),            do: {2, 5, 29, 36}
  def oid(:"id-ce-extKeyUsage"),                  do: {2, 5, 29, 37}
  def oid(:"id-ce-authorityAttributeIdentifier"), do: {2, 5, 29, 38}
  def oid(:"id-ce-roleSpecCertIdentifier"),       do: {2, 5, 29, 39}
  def oid(:"id-ce-cRLStreamIdentifier"),          do: {2, 5, 29, 40}
  def oid(:"id-ce-basicAttConstraints"),          do: {2, 5, 29, 41}
  def oid(:"id-ce-delegatedNameConstraints"),     do: {2, 5, 29, 42}
  def oid(:"id-ce-timeSpecification"),            do: {2, 5, 29, 43}
  def oid(:"id-ce-crlScope"),                     do: {2, 5, 29, 44}
  def oid(:"id-ce-statusReferrals"),              do: {2, 5, 29, 45}
  def oid(:"id-ce-freshestCRL"),                  do: {2, 5, 29, 46}
  def oid(:"id-ce-orderedList"),                  do: {2, 5, 29, 47}
  def oid(:"id-ce-attributeDescriptor"),          do: {2, 5, 29, 48}
  def oid(:"id-ce-userNotice"),                   do: {2, 5, 29, 49}
  def oid(:"id-ce-sOAIdentifier"),                do: {2, 5, 29, 50}
  def oid(:"id-ce-baseUpdateTime"),               do: {2, 5, 29, 51}
  def oid(:"id-ce-acceptableCertPolicies"),       do: {2, 5, 29, 52}
  def oid(:"id-ce-deltaInfo"),                    do: {2, 5, 29, 53}
  def oid(:"id-ce-inhibitAnyPolicy"),             do: {2, 5, 29, 54}
  def oid(:"id-ce-targetingInformation"),         do: {2, 5, 29, 55}
  def oid(:"id-ce-noRevAvail"),                   do: {2, 5, 29, 56}
  def oid(:"id-ce-acceptablePrivilegePolicies"),  do: {2, 5, 29, 57}
  def oid(:"id-ce-toBeRevoked"),                  do: {2, 5, 29, 58}
  def oid(:"id-ce-revokedGroups"),                do: {2, 5, 29, 59}
  def oid(:"id-ce-expiredCertsOnCRL"),            do: {2, 5, 29, 60}
  def oid(:"id-ce-indirectIssuer"),               do: {2, 5, 29, 61}
  def oid(:"id-ce-noAssertion"),                  do: {2, 5, 29, 62}
  def oid(:"id-ce-aAissuingDistributionPoint"),   do: {2, 5, 29, 63}
  def oid(:"id-ce-issuedOnBehalfOf"),             do: {2, 5, 29, 64}
  def oid(:"id-ce-singleUse"),                    do: {2, 5, 29, 65}
  def oid(:"id-ce-groupAC"),                      do: {2, 5, 29, 66}
  def oid(:"id-ce-allowedAttributeAssignments"),  do: {2, 5, 29, 67}
  def oid(:"id-ce-attributeMappings"),            do: {2, 5, 29, 68}
  def oid(:"id-ce-holderNameConstraints"),        do: {2, 5, 29, 69}
  def oid(:"id-ce-authorizationValidation"),      do: {2, 5, 29, 70}
  def oid(:"id-ce-protRestrict"),                 do: {2, 5, 29, 71}
  def oid(:"id-ce-subjectAltPublicKeyInfo"),      do: {2, 5, 29, 72}
  def oid(:"id-ce-altSignatureAlgorithm"),        do: {2, 5, 29, 73}
  def oid(:"id-ce-altSignatureValue"),            do: {2, 5, 29, 74}
  def oid(:"id-ce-associatedInformation"),        do: {2, 5, 29, 75}

  def pair([],acc), do: acc
  def pair([x],acc), do: [x|acc]
  def pair([a,b|t],acc), do: pair(t,[{hd(mapOids([:oid.decode(a)])),b}|acc])

  def mapOidsDecode(list) do
      :lists.map(fn x ->
         :erlang.iolist_to_binary(:string.join(:lists.map(fn y -> :erlang.integer_to_list(y) end,
         :erlang.tuple_to_list(:oid.decode(x))),'.')) end, list)
  end

  def mapOid(x)     do :erlang.iolist_to_binary(:string.join(:lists.map(fn y -> :erlang.integer_to_list(y) end, :erlang.tuple_to_list(x)),'.')) end
  def mapOids(list) do :lists.map(fn x -> mapOid(x) end, list) end
  def isString(bin) do :lists.foldl(fn x, acc when x < 20 -> acc + 1 ; _, acc -> acc end, 0, :erlang.binary_to_list(bin)) <= 0 end

  def oid({1,3,6,1,5,5,7,1,1}, v),        do: {:authorityInfoAccess, pair(v,[])}
  def oid({1,3,6,1,4,1,11129,2,4,2}, v),  do: {:signedCertificateTimestamp, :base64.encode(hd(pair(v,[])))}
  def oid({1,3,6,1,5,5,7,1,11},v),        do: {:subjectInfoAccess, pair(v,[])}
  def oid({1,3,6,1,5,5,7,1,3}, v),        do: {:qcStatements, :lists.map(fn x -> case isString(x) do false -> mapOid(:oid.decode(x)) ; true -> x end end, v) }
  def oid({2,5,29,9},v),                  do: {:subjectDirectoryAttributes, pair(v,[])}
  def oid({2,5,29,14},v),                 do: {:subjectKeyIdentifier, :base64.encode(hd(pair(v,[])))}
  def oid({2,5,29,15},[v]),               do: {:keyUsage, CA.EST.decodeKeyUsage(<<3,2,v::binary>>) }
  def oid({2,5,29,16},v),                 do: {:privateKeyUsagePeriod, v}
  def oid({2,5,29,17},v),                 do: {:subjectAltName, :lists.map(fn x -> case isString(x) do false -> mapOid(:oid.decode(x)) ; true -> x end end, v) }
  def oid({2,5,29,37},v),                 do: {:extKeyUsage, mapOids(:lists.map(fn x -> :oid.decode(x) end, v)) }
  def oid({2,5,29,19},v),                 do: {:basicConstraints, v}
  def oid({2,5,29,31},v),                 do: {:cRLDistributionPoints, pair(v,[])}
  def oid({2,5,29,32},v),                 do: {:certificatePolicies, :lists.map(fn x -> case isString(x) do false -> mapOid(:oid.decode(x)) ; true -> x end end, v) }
  def oid({2,5,29,35},v),                 do: {:authorityKeyIdentifier, v}
  def oid({2,5,29,46},v),                 do: {:freshestCRL, pair(v,[])}
  def oid({1,2,840,113549,1,9,3},v),      do: {:contentType, CA.AT.oid(CA.EST.decodeObjectIdentifier(v)) }
  def oid({1,2,840,113549,1,9,4},v),      do: {:messageDigest, :base64.encode(:erlang.element(2,:KEP.decode(:MessageDigest, v)))}
  def oid({1,2,840,113549,1,9,5},v),      do: {:signingTime, :erlang.element(2,:erlang.element(1,:asn1rt_nif.decode_ber_tlv(v)))}
  def oid({1,2,840,113549,1,9,16,2,14},v) do
      {:ok, {:ContentInfo, oid, value}} = :KEP.decode(:ContentInfo,v)
      {:ok, {:SignedData, _, _alg, {_,_,x}, _c, _x1, _si}} = :KEP.decode(:SignedData, value)
      {:ok, {:TSTInfo, _vsn, _oid, {:MessageImprint, _, x}, serial, ts, _,_,_,_}} = :KEP.decode(:TSTInfo, x)
      {:timeStampToken, {hd(mapOids([oid])), serial, :erlang.iolist_to_binary(ts), :base64.encode(x)}}
      end
  def oid({1,2,840,113549,1,9,16,2,18},v) do {:signerAttr, v} end
  def oid({1,2,840,113549,1,9,16,2,19},v) do {:otherSigCert, v} end
  def oid({1,2,840,113549,1,9,16,2,20},v) do
      {:ok, {:ContentInfo, oid, value}} = :KEP.decode(:ContentInfo,v)
      {:ok, {:SignedData, _, _alg, {_,_,x}, _c, _x1, _si}} = :KEP.decode(:SignedData, value)
      {:ok, {:TSTInfo, _vsn, _oid, {:MessageImprint, _, x}, serial, ts, _,_,_,_}} = :KEP.decode(:TSTInfo, x)
      {:contentTimestamp, {hd(mapOids([oid])), serial, :erlang.iolist_to_binary(ts), :base64.encode(x)}}
  end
  def oid({1,2,840,113549,1,9,16,2,22},v) do
      {:ok, x} = :KEP.decode(:CompleteRevocationRefs, v)
      {:revocationRefs, x}
  end
  def oid({1, 2, 840, 113549, 1, 9, 16, 2, 21}, v) do
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
      list = :lists.map(fn {:BasicOCSPResponse,{:ResponseData,_ver,{_,rdn},_time,_responses,_ext},_alg,_bin,_} -> CA.RDN.rdn(rdn) end, list)
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

end