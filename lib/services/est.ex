defmodule CA.EST do
  @moduledoc "CA/EST server."
  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  # Authority PKI X.509 EST RFC 7030

  post "/.well-known/est/simpleenroll" do CA.EST.Post.post(conn, [], "Authority", [], "ENROLL") end
  put  "/.well-known/est/simplereenroll" do CA.EST.Put.put(conn, [], "Authority", [], "RE-ENROLL") end
  get  "/.well-known/est/cacerts"        do CA.EST.Get.get(conn, [], "Authority", [], "CHECK") end
  get  "/.well-known/est/csrattrs"       do CA.EST.Get.get(conn, [], "Authority", [], "ABAC") end
  put  "/.well-known/est/fullcmc"        do CA.EST.Put.put(conn, [], "Authority", [], "CMC") end

  # See Page 36 of RFC 7030

  # iex(37)> :"EST".decode(:CsrAttrs, y)
  # {:ok,
  #  [
  #    oid: {1, 2, 840, 113549, 1, 9, 7},
  #    attribute: {:Attribute, {1, 2, 840, 10045, 2, 1},
  #     [<<6, 5, 43, 129, 4, 0, 34>>]},
  #    attribute: {:Attribute, {1, 2, 840, 113549, 1, 9, 14},
  #     [<<6, 7, 43, 6, 1, 1, 1, 1, 22>>]},
  #    oid: {1, 2, 840, 10045, 4, 3, 3}
  #  ]}
  # iex(38)> y
  # <<48, 65, 6, 9, 42, 134, 72, 134, 247, 13, 1, 9, 7, 48, 18, 6, 7, 42, 134, 72,
  #   206, 61, 2, 1, 49, 7, 6, 5, 43, 129, 4, 0, 34, 48, 22, 6, 9, 42, 134, 72, 134,
  #   247, 13, 1, 9, 14, 49, 9, 6, 7, ...>>
  # iex(39)> x
  # "MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJBgcrBgEBAQEWBggqhkjOPQQDAw=="

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
