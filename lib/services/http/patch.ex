defmodule CA.EST.Patch do
  import Plug.Conn
  def patch(conn,_,type,id,spec) do
#      :io.format 'PUT/4:#{type}#{id}/#{spec}', []
      send_resp(conn, 200, CA.EST.encode(%{"type" => type, "id" => id, "spec" => spec}))
  end
end
