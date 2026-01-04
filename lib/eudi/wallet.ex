defmodule CA.EUDI.Wallet do
  @moduledoc "EUDI/OID4VC Wallet web application server."
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
        id: EUDI.Wallet,
        start: {CA.EUDI.Wallet, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent
      }
  end

  get "/wallets" do CA.EST.Get.get(conn, "EUDI", [], [], "WALLETS") end
  get "/wallets/:id/dids" do CA.EST.Get.get(conn, "EUDI", [], [], "DIDS") end
  get "/wallets/:id/keys" do CA.EST.Get.get(conn, "EUDI", [], [], "KEYS") end
  get "/wallets/:id/credentials" do CA.EST.Get.get(conn, "EUDI", [], [], "CREDS") end
  get "/wallets/:id/issuers" do CA.EST.Get.get(conn, "EUDI", [], [], "ISSUERS") end
  get "/wallets/:id/exchange" do CA.EST.Get.get(conn, "EUDI", [], [], "EXCHANGES") end
  get "/wallets/parseMDoc" do CA.EST.Get.get(conn, "EUDI", [], [], "MDOC") end

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
