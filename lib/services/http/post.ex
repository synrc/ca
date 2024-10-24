defmodule CA.HTTP.Post do
  import Plug.Conn
  def post(conn,_,type,id,spec) do
#      :io.format 'PUT/4:#{type}#{id}/#{spec}', []
      send_resp(conn, 200, CA.HTTP.encode(%{"type" => type, "id" => id, "spec" => spec}))
  end
end
