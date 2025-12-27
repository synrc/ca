defmodule CA.RDN do
  @moduledoc "CA RDN OIDs."

  def encodeAttrs({:rdnSequence, attrs}) do
      {:rdnSequence, :lists.map(fn
          [{t,oid,{:uTF8String,x}}]      -> encodeString(t,oid,x,12)
          [{t,oid,x}] when is_list(x)    -> encodeString(t,oid,x,19)
                                       x -> x end, attrs)}
  end

  def decodeAttrs({:rdnSequence, attrs}) do
      {:rdnSequence, :lists.map(fn
           [{t,oid,{:uTF8String,x}}]      -> decodeString(t,oid,x,:uTF8String)
           [{t,oid,{:printableString,x}}] -> decodeString(t,oid,x,:printableString)
           [{t,oid,x}] when is_list(x)    -> decodeString(t,oid,x,:correct) # OTP 28
#          [{t,oid,x}] when is_list(x)    -> [{t,oid,x}] # OTP 27
           [{t,oid,x}] when is_binary(x)  -> decodeString(t,oid,x,:uTF8String)
                                       x  -> x end, attrs)}
  end

  def decodeString(t,oid,x,tag) do [{t,oid,{tag,x}}] end
  def encodeString(t,oid,x,code) do [{t,oid,:asn1rt_nif.encode_ber_tlv({code, :erlang.iolist_to_binary(x)})}] end

  def profile(csr) do
      {:CertificationRequest, {:CertificationRequestInfo, _ver, _subj, subjectPKI, _attr}, _signatureAlg, _signature} = csr
      {_, {_, {1,2,840,10045,2,1}, {:asn1_OPENTYPE,x}}, _} = subjectPKI
      {{6,oid},_} = :asn1rt_nif.decode_ber_tlv(x)
      {alg,_} = CA.ALG.lookup(:oid.decode(oid))
      "#{alg}"
  end

  def encodeAttrsCSR(csr) do
      {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
      {:CertificationRequest, {:CertificationRequestInfo, v, encodeAttrs(subj), x, y}, b, c}
  end

  def decodeAttrsCSR(csr) do
      {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
      {:CertificationRequest, {:CertificationRequestInfo, v, decodeAttrs(subj), x, y}, b, c}
  end

  def decodeAttrsCert(cert) do
      {cCertificate,{tTBSCertificate,:v3,a,ai,rdn1,v,rdn2,{p1,{p21,p22,_pki},p3},b,c,ext},ai,code} =
         :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
      {cCertificate,{tTBSCertificate,:v3,a,ai,decodeAttrs(rdn1),v,decodeAttrs(rdn2),
           {p1,{p21,p22,{:namedCurve,{1,3,132,0,34}}},p3},b,c,ext},ai,code}
  end

  def encodeAttrsCert(cert) do
      {cCertificate,{tTBSCertificate,:v3,a,ai,rdn1,v,rdn2,{p1,{p21,p22,pki},p3},b,c,ext},ai,code} =
         :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
      {cCertificate,{tTBSCertificate,:v3,a,ai,encodeAttrs(rdn1),v,encodeAttrs(rdn2),
           {p1,{p21,p22,pki},p3},b,c,ext},ai,code}
  end

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

end