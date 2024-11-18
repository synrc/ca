defmodule CA.EUDI.Verifier do
  @moduledoc "EUDI/OID4VC Verifier."
  @profiles  [ "secp256k1", "secp384r1", "secp521r1" ]
  @templates [ "ocsp", "ipsec", "bgp", "eap", "cap", "sip", "cmc", "scvp", "ssh", "tls" ]
  @classes   [ "ca", "ra", "server", "client", "human", "program" ]

  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  def start_link(opt) do
      Bandit.start_link(opt)
  end

  def child_spec(opt) do
      %{
        id: EUDI.Verifier,
        start: {CA.EUDI.Verifier, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent
      }
  end

  get "/openid4vc/session/:id" do CA.EST.Get.get(conn, "EUDI", [], id, "SESSION") end
  get "/openid4vc/policy-list" do CA.EST.Get.get(conn, "EUDI", [], [], "POLICIES") end
  get "/openid4vc/pd/:id" do CA.EST.Get.get(conn, "EUDI", [], id, "PD") end
  get "/openid4vc/verify/:state" do CA.EST.Get.get(conn, "EUDI", [], state, "VERIFY") end
  get "/openid4vc/request/:id" do CA.EST.Get.get(conn, "EUDI", [], id, "REQ") end

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
