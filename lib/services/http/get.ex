defmodule CA.EST.Get do
  @moduledoc "CA/EST GET Method HTTP handlers."
  @profiles ["secp256k1", "secp384r1", "secp521r1"]
  import Plug.Conn

  def get(conn, "CA", profile, template, op) do
    profile_name = if profile in @profiles, do: profile, else: "secp384r1"
    get_profile(conn, "CA", profile_name, template, op)
  end

  def get(conn, _authority, curve, template, operation) do
    send_resp(conn, 200, CA.EST.encode([%{"template" => template, "curve" => curve, "operation" => operation}]))
  end

  def get_profile(conn, "CA", profile, _, "CA") do
    body = :base64.encode(CA.CSR.read_ca_public(profile))

    conn
    |> put_resp_content_type("application/pkix-cert")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def get_profile(conn, "CA", profile, _, "CMS") do
    ca = CA.CSR.read_ca_public(profile)
    body = CA.CMS.signed_data([ca]) |> :base64.encode()

    conn
    |> put_resp_content_type("application/pkcs7-mime")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def get_profile(conn, "CA", _profile, _, "ABAC") do
    body = :base64.encode(CA.EST.csrattributes())

    conn
    |> put_resp_content_type("application/csrattrs")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def get_profile(conn, "CA", profile, _, "ROOT") do
    ca = CA.CSR.read_ca_public(profile)
    body = CA.CMS.signed_data([ca]) |> :base64.encode()

    conn
    |> put_resp_content_type("application/pkcs7-mime")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def get_profile(conn, "CA", _profile, _, "TEMPLATE") do
    body = :base64.encode(CA.EST.csrattributes())

    conn
    |> put_resp_content_type("application/csrattrs")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def get_profile(conn, "CA", profile, _, "CRL") do
    crl = CA.EST.CRL.generate(profile)
    body = :base64.encode(crl)

    conn
    |> put_resp_content_type("application/pkcs7-crl")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end
end
