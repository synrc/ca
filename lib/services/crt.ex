defmodule CA.CRT do
  @moduledoc "X.509 Certificates."

  def subj({:rdnSequence, attrs}) do
      {:rdnSequence, :lists.map(fn
          [{t,oid,{:uTF8String,x}}]   -> [{t,oid,:asn1rt_nif.encode_ber_tlv({12, :erlang.iolist_to_binary(x)})}]
          [{t,oid,x}] when is_list(x) -> [{t,oid,:asn1rt_nif.encode_ber_tlv({19, :erlang.iolist_to_binary(x)})}]
          [{t,oid,x}] -> [{t,oid,x}] end, attrs)}
  end

  def unsubj({:rdnSequence, attrs}) do
      {:rdnSequence, :lists.map(fn [{t,oid,x}] when is_binary(x) ->
           case :asn1rt_nif.decode_ber_tlv(x) do
                {{12,a},_} -> [{t,oid,{:uTF8String,a}}]
                {{19,a},_} -> [{t,oid,:erlang.binary_to_list(a)}]
           end
           {t,oid,x} -> [{t,oid,x}]
           x -> x
      end, attrs)}
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

  def rdn({0,9,2342,19200300,100,1,25}), do: :dc # "domainComponent"
  def rdn({1,2,840,113549,1,9,1}),       do: :e  # "emailAddress"

  def rdn({2, 5, 6, 1}),  do: :alias
  def rdn({2, 5, 6, 2}),  do: :country
  def rdn({2, 5, 6, 3}),  do: :locality
  def rdn({2, 5, 6, 4}),  do: :organization
  def rdn({2, 5, 6, 5}),  do: :organizationalUnit
  def rdn({2, 5, 6, 6}),  do: :person
  def rdn({2, 5, 6, 7}),  do: :organizationalPerson
  def rdn({2, 5, 6, 8}),  do: :organizationalRole
  def rdn({2, 5, 6, 9}),  do: :groupOfNames
  def rdn({2, 5, 6, 10}), do: :residentialPerson
  def rdn({2, 5, 6, 11}), do: :applicationProcess
  def rdn({2, 5, 6, 12}), do: :applicationEntity
  def rdn({2, 5, 6, 13}), do: :dSA
  def rdn({2, 5, 6, 14}), do: :device
  def rdn({2, 5, 6, 15}), do: :strongAuthenticationUser
  def rdn({2, 5, 6, 16}), do: :certificationAuthority
  def rdn({2, 5, 6, 17}), do: :groupOfUniqueNames
  def rdn({2, 5, 6, 18}), do: :userSecurityInformation
  def rdn({2, 5, 6, 19}), do: :cRLDistributionPoint
  def rdn({2, 5, 6, 20}), do: :dmd
  def rdn({2, 5, 6, 21}), do: :pkiUser
  def rdn({2, 5, 6, 22}), do: :pkiCA
  def rdn({2, 5, 6, 23}), do: :deltaCRL
  def rdn({2, 5, 6, 24}), do: :pmiUser
  def rdn({2, 5, 6, 25}), do: :pmiAA
  def rdn({2, 5, 6, 26}), do: :pmSOA
  def rdn({2, 5, 6, 27}), do: :attCertCRLDistributionPts
  def rdn({2, 5, 6, 28}), do: :parent
  def rdn({2, 5, 6, 29}), do: :child
  def rdn({2, 5, 6, 30}), do: :cpCps
  def rdn({2, 5, 6, 31}), do: :pkiCertPath
  def rdn({2, 5, 6, 32}), do: :privilegePolicy
  def rdn({2, 5, 6, 33}), do: :pmiDelegationPath
  def rdn({2, 5, 6, 34}), do: :protectedPrivilegePolicy
  def rdn({2, 5, 6, 35}), do: :oidC1obj
  def rdn({2, 5, 6, 36}), do: :oidC2obj
  def rdn({2, 5, 6, 37}), do: :oidCobj
  def rdn({2, 5, 6, 38}), do: :isoTagInfo
  def rdn({2, 5, 6, 39}), do: :isoTagType
  def rdn({2, 5, 6, 41}), do: :userPwdClass
  def rdn({2, 5, 6, 42}), do: :urnCobj
  def rdn({2, 5, 6, 43}), do: :epcTagInfoObj
  def rdn({2, 5, 6, 44}), do: :epcTagTypeObj

  def rdn({2, 5, 4, 1}),  do: :aliasedEntryName
  def rdn({2, 5, 4, 2}),  do: :knowledgeInformation
  def rdn({2, 5, 4, 5}),  do: :serialNumber
  def rdn({2, 5, 4, 3}),  do: :cn     # "commonName"
  def rdn({2, 5, 4, 4}),  do: :sn     # "surname"
  def rdn({2, 5, 4, 6}),  do: :c      # "country"
  def rdn({2, 5, 4, 7}),  do: :l      # "localityName"
  def rdn({2, 5, 4, 8}),  do: :st     # "stateOrProvinceName"
  def rdn({2, 5, 4, 10}), do: :o      # "organization"
  def rdn({2, 5, 4, 11}), do: :ou     # "organizationalUnit"
  def rdn({2, 5, 4, 12}), do: :title
  def rdn({2, 5, 4, 13}), do: :description
  def rdn({2, 5, 4, 14}), do: :device
  def rdn({2, 5, 4, 15}), do: :businessCategory
  def rdn({2, 5, 4, 16}), do: :postalAddress
  def rdn({2, 5, 4, 17}), do: :postalCode
  def rdn({2, 5, 4, 18}), do: :postOfficeBox
  def rdn({2, 5, 4, 19}), do: :physicalDeliveryOfficeName
  def rdn({2, 5, 4, 20}), do: :telephoneNumber
  def rdn({2, 5, 4, 21}), do: :telexNumber
  def rdn({2, 5, 4, 22}), do: :teletexTerminalIdentifier
  def rdn({2, 5, 4, 23}), do: :facsimileTelephoneNumber
  def rdn({2, 5, 4, 24}), do: :x121Address
  def rdn({2, 5, 4, 25}), do: :internationalISDNNumber
  def rdn({2, 5, 4, 26}), do: :registeredAddress
  def rdn({2, 5, 4, 27}), do: :destinationIndicator
  def rdn({2, 5, 4, 28}), do: :preferredDeliveryMethod
  def rdn({2, 5, 4, 29}), do: :presentationAddress
  def rdn({2, 5, 4, 30}), do: :supportedApplicationContext
  def rdn({2, 5, 4, 31}), do: :member
  def rdn({2, 5, 4, 32}), do: :owner
  def rdn({2, 5, 4, 33}), do: :roleOccupant
  def rdn({2, 5, 4, 34}), do: :seeAlso
  def rdn({2, 5, 4, 35}), do: :userPassword
  def rdn({2, 5, 4, 36}), do: :userCertificate
  def rdn({2, 5, 4, 37}), do: :cACertificate
  def rdn({2, 5, 4, 38}), do: :authorityRevocationList
  def rdn({2, 5, 4, 39}), do: :certificateRevocationList
  def rdn({2, 5, 4, 40}), do: :crossCertificatePair
  def rdn({2, 5, 4, 41}), do: :name
  def rdn({2, 5, 4, 42}), do: :givenName
  def rdn({2, 5, 4, 43}), do: :initials
  def rdn({2, 5, 4, 44}), do: :generationQualifier
  def rdn({2, 5, 4, 45}), do: :uniqueIdentifier
  def rdn({2, 5, 4, 46}), do: :dnQialifier
  def rdn({2, 5, 4, 47}), do: :enhancedSearchGuide
  def rdn({2, 5, 4, 48}), do: :protocolInformation
  def rdn({2, 5, 4, 49}), do: :distinguishedName
  def rdn({2, 5, 4, 50}), do: :uniqueMember
  def rdn({2, 5, 4, 51}), do: :houseIdentifier
  def rdn({2, 5, 4, 52}), do: :supportedAlgorithms
  def rdn({2, 5, 4, 53}), do: :deltaRevocationList
  def rdn({2, 5, 4, 54}), do: :dmdName
  def rdn({2, 5, 4, 55}), do: :clearance
  def rdn({2, 5, 4, 56}), do: :defaultDirQop
  def rdn({2, 5, 4, 57}), do: :attributeIntegrityInfo
  def rdn({2, 5, 4, 58}), do: :attributeCertificate
  def rdn({2, 5, 4, 59}), do: :attributeCertificateRevocationList
  def rdn({2, 5, 4, 60}), do: :confKeyInfo
  def rdn({2, 5, 4, 61}), do: :aACertificate
  def rdn({2, 5, 4, 62}), do: :attributeDescriptorCertificate
  def rdn({2, 5, 4, 63}), do: :attributeAuthorityRevocationList
  def rdn({2, 5, 4, 64}), do: :familyInformation
  def rdn({2, 5, 4, 65}), do: :pseudonym
  def rdn({2, 5, 4, 66}), do: :communicationsService
  def rdn({2, 5, 4, 67}), do: :communicationsNetwork
  def rdn({2, 5, 4, 68}), do: :certificationPracticeStmt
  def rdn({2, 5, 4, 69}), do: :certificatePolicy
  def rdn({2, 5, 4, 70}), do: :pkiPath
  def rdn({2, 5, 4, 71}), do: :privPolicy
  def rdn({2, 5, 4, 72}), do: :role
  def rdn({2, 5, 4, 73}), do: :delegationPath
  def rdn({2, 5, 4, 74}), do: :protPrivPolicy
  def rdn({2, 5, 4, 75}), do: :xMLPrivilegeInfo
  def rdn({2, 5, 4, 76}), do: :xmlPrivPolicy
  def rdn({2, 5, 4, 77}), do: :uuidpair
  def rdn({2, 5, 4, 78}), do: :tagOid
  def rdn({2, 5, 4, 79}), do: :uiiFormat
  def rdn({2, 5, 4, 80}), do: :uiiInUrh
  def rdn({2, 5, 4, 81}), do: :contentUrl
  def rdn({2, 5, 4, 82}), do: :permission
  def rdn({2, 5, 4, 83}), do: :uri
  def rdn({2, 5, 4, 86}), do: :urn
  def rdn({2, 5, 4, 87}), do: :url
  def rdn({2, 5, 4, 88}), do: :utmCoordinates
  def rdn({2, 5, 4, 89}), do: :urnC
  def rdn({2, 5, 4, 90}), do: :uii
  def rdn({2, 5, 4, 91}), do: :epc
  def rdn({2, 5, 4, 92}), do: :tagAfi
  def rdn({2, 5, 4, 93}), do: :epcFormat
  def rdn({2, 5, 4, 94}), do: :epcInUrn
  def rdn({2, 5, 4, 95}), do: :ldapUrl
  def rdn({2, 5, 4, 97}), do: :organizationIdentifier
  def rdn({2, 5, 4, 98}), do: :countryCode3c
  def rdn({2, 5, 4, 99}), do: :countryCode3n

  def rdn({2, 5, 4, 100}), do: :dnsName
  def rdn({2, 5, 4, 101}), do: :eepkCertificateRevocationList
  def rdn({2, 5, 4, 102}), do: :eeAttrCertificateRevocationList
  def rdn({2, 5, 4, 103}), do: :supportedPublicKeyAlgorithms
  def rdn({2, 5, 4, 104}), do: :intEmail
  def rdn({2, 5, 4, 105}), do: :jid
  def rdn({2, 5, 4, 106}), do: :objectIdentifier

  def rdn({:rdnSequence, list}) do
      :lists.map(fn [{_,oid,{_,list}}] -> {rdn(oid),"#{list}"}
                    [{_,oid,list}]     -> {rdn(oid),"#{list}"}
                     {_,oid,{_,list}}  -> {rdn(oid),"#{list}"}
                     {_,oid,   list}   -> {rdn(oid),"#{list}"}
                                     x -> x end, list)
  end
  def rdn(x),  do: "#{x}"

  def rdn2({:rdnSequence, list}) do
      Enum.join :lists.map(fn [{_,oid,{_,list}}] -> "#{rdn(oid)}=#{list}"
                               {_,oid,{_,list}}  -> "#{rdn(oid)}=#{list}"
                               {_,oid,   list}   -> "#{rdn(oid)}=#{list}" end, list), "/"
  end

  def baseLength(oid) when is_tuple(oid) do CA.Curve.getLength(CA.KnownCurves.getCurveByOid(oid)) end
  def baseLength(_) do 256 end

  def decodePointFromPublic(agreement,params,publicKey) do
      bin = :binary.part(publicKey,1,:erlang.size(publicKey)-1)
      baseLength = baseLength(params)
      xs = :binary.part(bin, 0, baseLength)
      ys = :binary.part(bin, baseLength, :erlang.size(bin) - baseLength)
      [ x: CA.ECDSA.numberFromString(xs),
        y: CA.ECDSA.numberFromString(ys),
        scheme: CA.AT.oid(agreement),
        curve: CA.AT.oid(params),
      ]
  end

  def decodePublicKey(agreement,{:asn1_OPENTYPE, params},publicKey) do decodePublicKey(agreement,params,publicKey) end
  def decodePublicKey(agreement,params,publicKey) do
      case agreement do
           {1,2,840,113549,1,1,1} -> # RSA
                {:ok, key} = :"PKCS-1".decode(:'RSAPublicKey', publicKey)
                [key: key, scheme: :RSA]
           {1,2,840,10045,2,1} -> # ECDSA
                params = CA.EST.decodeObjectIdentifier(params)
                decodePointFromPublic(agreement,params,publicKey)
           {1,2,804,2,1,1,1,1,3,1,1} -> # ДСТУ-4145, ДСТУ-7564
                {:ok,p} = :DSTU.decode(:DSTU4145Params, params)
                [key: publicKey, scheme: CA.AT.oid(agreement), field: p]
           _ -> :io.format 'new publicKey agreement scheme detected: ~p~n', [agreement]
                :base64.encode publicKey
      end
  end

  def parseCertPEM(file)  do {:ok, bin} = :file.read_file file ; list = :public_key.pem_decode(bin) ; :lists.map(fn x -> parseCert(:public_key.pem_entry_decode(x)) end, list) end
  def parseCertB64(file)  do {:ok, bin} = :file.read_file file ; parseCertBin(:base64.decode(bin)) end
  def parseCertFile(file) do {:ok, bin} = :file.read_file file ; parseCertBin(bin) end
  def parseCertBin(bin)   do {:ok, cert} = :"AuthenticationFramework".decode(:Certificate, bin) ; parseCert(cert) end

  def parseCert(cert, _) do parseCert(cert) end
  def parseCert({:certificate, cert}) do parseCert(cert) end
  def parseCert(cert) do
      {:Certificate, tbs, _, _} = case cert do
         {:Certificate, tbs, x, y} -> {:Certificate, tbs, x, y}
         {:Certificate, tbs, x, y, _} -> {:Certificate, tbs, x, y}
      end

      {_, ver, serial, {_,alg,_}, issuer, {_,{_,nb},{_,na}}, issuee,
         {:SubjectPublicKeyInfo, {_, agreement, params}, publicKey}, _b, _c, exts} = tbs
      extensions = :lists.map(fn {:Extension,code,_x,b} ->
         oid(code, :lists.flatten(flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
      [ resourceType: :Certificate,
        version: ver,
        signatureAlgorithm: CA.AT.oid(alg),
        subject: rdn(unsubj(issuee)),
        issuer:  rdn(unsubj(issuer)),
        serial: :base64.encode(CA.EST.integer(serial)),
        validity: [from: nb, to: na],
        publicKey: decodePublicKey(agreement, params, publicKey),
        extensions: extensions
      ]
  end

end
