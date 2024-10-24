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

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.\n") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
