defmodule CA.EST.Get do
  import Plug.Conn

  def get(conn, [], "Authority", [], "CA") do
      body = :base64.encode(CA.CSR.read_ca_public())
      conn |> put_resp_content_type("application/pkix-cert")
           |> put_resp_header("Content-Transfer-Encoding", "base64")
           |> put_resp_header("Content-Length", :erlang.integer_to_binary(:erlang.size(body)))
           |> resp(200, body)
           |> send_resp()
  end

  def get(conn, [], "Authority", [], "CMS") do
      ca = CA.CSR.read_ca_public()
      {:ok, cacert} = :"PKIX1Explicit-2009".decode(:Certificate, ca)
      ci = {:ContentInfo, {1, 2, 840, 113549, 1, 7, 2},
             {:SignedData, :v1, [],
               {:EncapsulatedContentInfo, {1, 2, 840, 113549, 1, 7, 1}, :asn1_NOVALUE},
                 [certificate: cacert], [], []}}
      {:ok, cms} = :"CryptographicMessageSyntax-2010".encode :ContentInfo, ci
      body = :base64.encode cms
      conn |> put_resp_content_type("application/pkcs7-mime")
           |> put_resp_header("Content-Transfer-Encoding", "base64")
           |> put_resp_header("Content-Length", :erlang.integer_to_binary(:erlang.size(body)))
           |> resp(200, body)
           |> send_resp()
  end

  def get(conn, [], "Authority", [], "ABAC") do
      body = :base64.encode(CA.EST.csrattributes())
      conn |> put_resp_content_type("application/csrattrs")
           |> put_resp_header("Content-Transfer-Encoding", "base64")
           |> put_resp_header("Content-Length", :erlang.integer_to_binary(:erlang.size(body)))
           |> resp(200, body)
           |> send_resp()
  end

  def get(conn, _, type, id, spec) do
      :io.format 'GET/4:#{type}/#{id}/#{spec}', []
      send_resp(conn, 200, CA.EST.encode([%{"type" => type, "id" => id, "spec" => spec}]))
  end

end