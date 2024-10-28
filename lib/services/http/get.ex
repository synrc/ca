defmodule CA.EST.Get do
  import Plug.Conn
  def get(conn, [], "Authority" = type, [] = id, "ABAC" = spec) do
      :io.format 'CSRATTRS: GET/4:#{type}/#{id}/#{spec}', []
      bin = CA.EST.csrattributes()
      base64 = :base64.encode(bin)
      conn |> put_resp_content_type("application/csrattrs")
           |> put_resp_header("Content-Transfer-Encoding", "base64")
           |> put_resp_header("Content-Length", :erlang.integer_to_binary(:erlang.size(base64)))
           |> resp(200, base64)
           |> send_resp()
  end
  def get(conn, _, type, id, spec) do
      :io.format 'GET/4:#{type}/#{id}/#{spec}', []
      send_resp(conn, 200, CA.EST.encode([%{"type" => type, "id" => id, "spec" => spec}]))
  end
end