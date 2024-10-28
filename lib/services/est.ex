defmodule CA.EST do
  @moduledoc "CA/EST TLS HTTP server."
  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

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

  post "/.well-known/est/simpleenroll"   do CA.EST.Post.post(conn, [], "Authority", [], "ENROLL") end
  put  "/.well-known/est/simplereenroll" do CA.EST.Put.put(conn,   [], "Authority", [], "RE-ENROLL") end
  get  "/.well-known/est/cacerts"        do CA.EST.Get.get(conn,   [], "Authority", [], "ROOT") end
  get  "/.well-known/est/csrattrs"       do CA.EST.Get.get(conn,   [], "Authority", [], "ABAC") end
  put  "/.well-known/est/fullcmc"        do CA.EST.Put.put(conn,   [], "Authority", [], "CMC") end

  # See Page 36 of RFC 7030

  def csrattributes() do
      {:ok, bin} = :"EST".encode(:CsrAttrs, [
         oid: CA.AT.oid(:"id-at-challengePassword"),
         oid: CA.X962.oid(:"id-ds-ecdsa-with-SHA384")
         attribute: {:Attribute, CA.X962.oid(:"id-kt-ecPublicKey"), [objectIdentifier(CA.ALG.oid(:secp384r1))] },
         attribute: {:Attribute, CA.AT.oid(:"id-at-rsaEncryption"), [integer(4096)]},
         attribute: {:Attribute, CA.AT.oid(:"id-at-extensionRequest"), [
                      extension({:Extension, CA.CE.oid(:"id-ce-keyUsage"), true, keyUsage([:digitalSignature, :keyCertSign, :cRLSign])}),
                      extension({:Extension, CA.CE.oid(:"id-ce-basicConstraints"), true, basicConstraints()}),
                      extension({:Extension, CA.CE.oid(:"id-ce-extKeyUsage"), false,
                                  extendedKeyUsage([ CA.KP.oid(:"id-kp-serverAuth"),
                                                     CA.KP.oid(:"id-kp-clientAuth"),
                                                     CA.KP.oid(:"id-kp-codeSigning"),
                                                     CA.KP.oid(:"id-kp-emailProtection") ])})
                    ]},
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
