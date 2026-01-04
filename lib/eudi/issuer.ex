defmodule CA.EUDI.Issuer do
  @moduledoc "EUDI/OID4VC Issuer server."
#  @profiles  [ "secp256k1", "secp384r1", "secp521r1" ]
#  @templates [ "ocsp", "ipsec", "bgp", "eap", "cap", "sip", "cmc", "scvp", "ssh", "tls" ]
#  @classes   [ "ca", "ra", "server", "client", "human", "program" ]

  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  def start_link(opt) do
      Bandit.start_link(opt)
  end

  def child_spec(opt) do
      %{
        id: EUDI.Issuer,
        start: {CA.EUDI.Issuer, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent
      }
  end

  get  "/jwks" do CA.EST.Get.get(conn, "EUDI", [], [], "JWKS") end
  get  "/.well-known/openid-configuration" do CA.EST.Get.get(conn, "EUDI", [], [], "CONFIG") end
  get  "/.well-known/openid-credential-issuer" do CA.EST.Get.get(conn, "EUDI", [], [], "ISSUE") end
  get  "/.well-known/oauth-authorization-server" do CA.EST.Get.get(conn, "EUDI", [], [], "OAUTH") end
  get  "/.well-known/jwt-vc-issuer" do CA.EST.Get.get(conn, "EUDI", [], [], "JWT") end
  get  "/openid4vc/credentialOffer" do CA.EST.Get.get(conn, "EUDI", [], [], "OFFER") end
  post "/openid4vc/jwt/issue" do CA.EST.Get.get(conn, "EUDI", [], [], "JWT") end
  post "/openid4vc/sdjwt/issue" do CA.EST.Get.get(conn, "EUDI", [], [], "SDJWT") end
  post "/openid4vc/mdoc/issue" do CA.EST.Get.get(conn, "EUDI", [], [], "MDOC") end

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
