defmodule CA.EST.Get do
  import Plug.Conn
  def get(conn,_,type,id,spec) do
#      :io.format 'GET/4:#{type}/#{id}/#{spec}', []
      send_resp(conn, 200, CA.EST.encode([%{"type" => type, "id" => id, "spec" => spec}]))
  end
end