defmodule CA.EST do
  @moduledoc "CA/EST TLS HTTP server."
  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

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

  # > :"EST".decode(:CsrAttrs, y)
  # {:ok,
  #  [
  #    oid: {1, 2, 840, 113549, 1, 9, 7},
  #    attribute: {:Attribute, {1, 2, 840, 10045, 2, 1}, [{1, 3, 132, 0, 34}]},
  #    attribute: {:Attribute, {1, 2, 840, 113549, 1, 9, 14}, [{1, 3, 6, 1, 1, 1, 1, 22}]},
  #    oid: {1, 2, 840, 10045, 4, 3, 3}
  #  ]}
  # > x
  # "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJBgcrBgEBAQEWBggqhkjOPQQDAw=="

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
