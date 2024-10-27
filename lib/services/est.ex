defmodule CA.EST do
  @moduledoc "CA/EST TLS HTTP server."
  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  def oid(:secp384r1), do: {1,3,132,0,34}
  def oid(:secp512r1), do: {1,3,132,0,35}

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

  def oid(:"id-kp-serverAuth"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 1}
  def oid(:"id-kp-clientAuth"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 2}
  def oid(:"id-kp-codeSigning"),                  do: {1, 3, 6, 1, 5, 5, 7, 3, 3}
  def oid(:"id-kp-emailProtection"),              do: {1, 3, 6, 1, 5, 5, 7, 3, 4}
  def oid(:"id-kp-ipsecEndSystem"),               do: {1, 3, 6, 1, 5, 5, 7, 3, 5}
  def oid(:"id-kp-ipsecTunnel"),                  do: {1, 3, 6, 1, 5, 5, 7, 3, 6}
  def oid(:"id-kp-ipsecUser"),                    do: {1, 3, 6, 1, 5, 5, 7, 3, 7}
  def oid(:"id-kp-timeStamping"),                 do: {1, 3, 6, 1, 5, 5, 7, 3, 8}
  def oid(:"id-kp-OCSPSigning"),                  do: {1, 3, 6, 1, 5, 5, 7, 3, 9}
  def oid(:"id-kp-dvcs"),                         do: {1, 3, 6, 1, 5, 5, 7, 3, 10}
  def oid(:"id-kp-sbgpCertAAServerAuth"),         do: {1, 3, 6, 1, 5, 5, 7, 3, 11}
  def oid(:"id-kp-scvp-responder"),               do: {1, 3, 6, 1, 5, 5, 7, 3, 12}
  def oid(:"id-kp-eapOverPPP"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 13}
  def oid(:"id-kp-eapOverLAN"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 14}
  def oid(:"id-kp-scvpServer"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 15}
  def oid(:"id-kp-scvpClient"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 16}
  def oid(:"id-kp-ipsecIKE"),                     do: {1, 3, 6, 1, 5, 5, 7, 3, 17}
  def oid(:"id-kp-capwapAC"),                     do: {1, 3, 6, 1, 5, 5, 7, 3, 18}
  def oid(:"id-kp-capwapWTP"),                    do: {1, 3, 6, 1, 5, 5, 7, 3, 19}
  def oid(:"id-kp-sipDomain"),                    do: {1, 3, 6, 1, 5, 5, 7, 3, 20}
  def oid(:"id-kp-secureShellClient"),            do: {1, 3, 6, 1, 5, 5, 7, 3, 21}
  def oid(:"id-kp-secureShellServer"),            do: {1, 3, 6, 1, 5, 5, 7, 3, 22}
  def oid(:"id-kp-sendRouter"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 23}
  def oid(:"id-kp-sendProxiedRouter"),            do: {1, 3, 6, 1, 5, 5, 7, 3, 24}
  def oid(:"id-kp-sendOwner"),                    do: {1, 3, 6, 1, 5, 5, 7, 3, 25}
  def oid(:"id-kp-sendProxiedOwner"),             do: {1, 3, 6, 1, 5, 5, 7, 3, 26}
  def oid(:"id-kp-cmcCA"),                        do: {1, 3, 6, 1, 5, 5, 7, 3, 27}
  def oid(:"id-kp-cmcRA"),                        do: {1, 3, 6, 1, 5, 5, 7, 3, 28}
  def oid(:"id-kp-cmcArchive"),                   do: {1, 3, 6, 1, 5, 5, 7, 3, 29}
  def oid(:"id-kp-bgpsec-router"),                do: {1, 3, 6, 1, 5, 5, 7, 3, 30}
  def oid(:"id-kp-BrandIndicatorforMessageIdentification"), do: {1, 3, 6, 1, 5, 5, 7, 3, 31}
  def oid(:"id-kp-cmKGA"),                        do: {1, 3, 6, 1, 5, 5, 7, 3, 32}
  def oid(:"id-kp-rpcTLSClient"),                 do: {1, 3, 6, 1, 5, 5, 7, 3, 33}
  def oid(:"id-kp-rpcTLSServer"),                 do: {1, 3, 6, 1, 5, 5, 7, 3, 34}
  def oid(:"id-kp-bundleSecurity"),               do: {1, 3, 6, 1, 5, 5, 7, 3, 35}
  def oid(:"id-kp-documentSigning"),              do: {1, 3, 6, 1, 5, 5, 7, 3, 36}
  def oid(:"id-kp-jwt"),                          do: {1, 3, 6, 1, 5, 5, 7, 3, 37}
  def oid(:"id-kp-httpContentEncrypt"),           do: {1, 3, 6, 1, 5, 5, 7, 3, 38}
  def oid(:"id-kp-oauthAccessTokenSigning"),      do: {1, 3, 6, 1, 5, 5, 7, 3, 39}


  def oid(:"id-at-rsaEncryption"),                        do: {1, 2, 840, 113549, 1, 1, 1}
  def oid(:"id-at-sha1WithRSAEncryption"),                do: {1, 2, 840, 113549, 1, 1, 5}
  def oid(:"id-at-sha512-256WithRSAEncryption"),          do: {1, 2, 840, 113549, 1, 1, 16}
  def oid(:"id-at-dhKeyAgreement"),                       do: {1, 2, 840, 113549, 1, 3, 1}
  def oid(:"id-at-emailAddress"),                         do: {1, 2, 840, 113549, 1, 9, 1}
  def oid(:"id-at-unstructuredName"),                     do: {1, 2, 840, 113549, 1, 9, 2}
  def oid(:"id-at-contentType"),                          do: {1, 2, 840, 113549, 1, 9, 3}
  def oid(:"id-at-messageDigest"),                        do: {1, 2, 840, 113549, 1, 9, 4}
  def oid(:"id-at-signingTime"),                          do: {1, 2, 840, 113549, 1, 9, 5}
  def oid(:"id-at-counterSignature"),                     do: {1, 2, 840, 113549, 1, 9, 6}
  def oid(:"id-at-challengePassword"),                    do: {1, 2, 840, 113549, 1, 9, 7}
  def oid(:"id-at-unstructuredAddress"),                  do: {1, 2, 840, 113549, 1, 9, 8}
  def oid(:"id-at-extendedCertificateAttributes"),        do: {1, 2, 840, 113549, 1, 9, 9}
  def oid(:"id-at-issuerAndSerialNumber"),                do: {1, 2, 840, 113549, 1, 9, 10}
  def oid(:"id-at-passwordCheck"),                        do: {1, 2, 840, 113549, 1, 9, 11}
  def oid(:"id-at-publicKey"),                            do: {1, 2, 840, 113549, 1, 9, 12}
  def oid(:"id-at-signingDescription"),                   do: {1, 2, 840, 113549, 1, 9, 13}
  def oid(:"id-at-extensionRequest"),                     do: {1, 2, 840, 113549, 1, 9, 14}
  def oid(:"id-at-smimeCapabilities"),                    do: {1, 2, 840, 113549, 1, 9, 15}

  def oid(:"id-ft-prime-field"),                          do: {1, 2, 840, 10045, 1, 1}
  def oid(:"id-ft-characteristic-two-field"),             do: {1, 2, 840, 10045, 1, 2}
  def oid(:"id-kt-ecPublicKey"),                          do: {1, 2, 840, 10045, 2, 1}
  def oid(:"id-ct-characteristicTwo"),                    do: {1, 2, 840, 10045, 3, 0}
  def oid(:"id-ct-prime"),                                do: {1, 2, 840, 10045, 3, 1}
  def oid(:"id-ds-ecdsa-with-SHA1"),                      do: {1, 2, 840, 10045, 4, 1}
  def oid(:"id-ds-ecdsa-with-Recommended"),               do: {1, 2, 840, 10045, 4, 2}
  def oid(:"id-ds-ecdsa-with-SHA2"),                      do: {1, 2, 840, 10045, 4, 3}
  def oid(:"id-ds-ecdsa-with-SHA224"),                    do: {1, 2, 840, 10045, 4, 3, 1}
  def oid(:"id-ds-ecdsa-with-SHA256"),                    do: {1, 2, 840, 10045, 4, 3, 2}
  def oid(:"id-ds-ecdsa-with-SHA384"),                    do: {1, 2, 840, 10045, 4, 3, 3}
  def oid(:"id-ds-ecdsa-with-SHA512"),                    do: {1, 2, 840, 10045, 4, 3, 4}

  def integer(x)             do {:ok, v} = :"EST".encode(:Int, x) ; v end
  def objectIdentifier(x)    do {:ok, v} = :"EST".encode(:OID, x) ; v end
  def extension(x)           do {:ok, v} = :"EST".encode(:Extension, x) ; v end

  def basicConstraints()     do {:ok, v} = :"PKIX1Implicit-2009".encode(:BasicConstraints, {:BasicConstraints, false, :asn1_NOVALUE}) ; v end
  def keyUsage(list)         do {:ok, v} = :"PKIX1Implicit-2009".encode(:KeyUsage, list) ; v end
  def extendedKeyUsage(list) do {:ok, v} = :"PKIX1Implicit-2009".encode(:ExtKeyUsageSyntax, list) ; v end

  def start() do 
      children = [ { Bandit, scheme: :http, port: 8047, plug: __MODULE__ } ]
      Supervisor.start_link(children, strategy: :one_for_one, name: CA.Supervisor)
  end

  # Authority PKI X.509 EST RFC 7030

  post "/.well-known/est/simpleenroll" do CA.EST.Post.post(conn, [], "Authority", [], "ENROLL") end
  put  "/.well-known/est/simplereenroll" do CA.EST.Put.put(conn, [], "Authority", [], "RE-ENROLL") end
  get  "/.well-known/est/cacerts"        do CA.EST.Get.get(conn, [], "Authority", [], "ROOT") end
  get  "/.well-known/est/csrattrs"       do CA.EST.Get.get(conn, [], "Authority", [], "ABAC") end
  put  "/.well-known/est/fullcmc"        do CA.EST.Put.put(conn, [], "Authority", [], "CMC") end

  # See Page 36 of RFC 7030

  def csrattributes() do
      {:ok, bin} = :"EST".encode(:CsrAttrs, [
         oid: oid(:"id-at-challengePassword"),
         attribute: {:Attribute, oid(:"id-kt-ecPublicKey"), [objectIdentifier(oid(:secp384r1))] },
         attribute: {:Attribute, oid(:"id-at-rsaEncryption"), [integer(4096)]},
         attribute: {:Attribute, oid(:"id-at-extensionRequest"), [
                      extension({:Extension, oid(:"id-ce-keyUsage"), true, keyUsage([:digitalSignature, :keyCertSign, :cRLSign])}),
                      extension({:Extension, oid(:"id-ce-basicConstraints"), true, basicConstraints()}),
                      extension({:Extension, oid(:"id-ce-extKeyUsage"), false,
                                  extendedKeyUsage([ oid(:"id-kp-serverAuth"),
                                                     oid(:"id-kp-clientAuth"),
                                                     oid(:"id-kp-codeSigning"),
                                                     oid(:"id-kp-emailProtection") ])})
                    ]},
         oid: oid(:"id-ds-ecdsa-with-SHA384")
      ])
      bin
  end

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
