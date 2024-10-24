defmodule CA.HTTP do
  use Plug.Router
  plug :match
  plug :dispatch
  plug Plug.Parsers, parsers: [:json], json_decoder: Jason

  # Authority PKI X.509 Enrollment Protocol over HTTP

  post   "/authority"              do     CA.HTTP.Post.post(conn, [], "Authority", [], "enroll") end
  get    "/authority/:id/validate" do       CA.HTTP.Get.get(conn, [], "Authority", id, "validate") end
  put    "/authority/:id/update"   do       CA.HTTP.Put.put(conn, [], "Authority", id, "update") end
  delete "/authority/:id"          do CA.HTTP.Delete.delete(conn, [], "Authority", id, "delete") end

  match _ do send_resp(conn, 404, "Please refer to https://authority.erp.uno for more information.") end
  def encode(x) do
      case Jason.encode(x) do
           {:ok, bin} -> bin
           {:error, _} -> ""
      end |> Jason.Formatter.pretty_print
  end
end
