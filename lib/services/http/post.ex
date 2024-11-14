defmodule CA.EST.Post do
  @moduledoc "CA/EST POST Method HTTP handlers."
  @profiles ["secp256k1","secp384r1","secp521r1"]
  @classes   [ "ca", "ra", "server", "client", "human", "program" ]

  import Plug.Conn
  require CA
  require CA.CMP
  require CA.CMP.Scheme

  def post(conn, "CA", profile, template, "PKCS-10") when profile in @profiles and template in @classes do

      {ca_key, ca} = CA.CSR.read_ca(profile)
      {:ok, body, _} = Plug.Conn.read_body(conn, [])
      bin = :base64.decode(:binary.part(body, 35, byte_size(body) - 68))
      {:ok, csr} = :"PKCS-10".decode :CertificationRequest, bin

      true = profile == CA.RDN.profile(csr)
      subject = X509.CSR.subject(csr)
      :logger.info 'HTTP P10CR from ~tp template ~tp profile ~p~n', [CA.RDN.rdn(subject), template, CA.RDN.profile(csr)]

      true = X509.CSR.valid?(CA.RDN.encodeAttrsCSR(csr))
      cert = X509.Certificate.new(X509.CSR.public_key(csr), CA.RDN.encodeAttrs(subject), ca, ca_key,
         extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

      reply = case Keyword.get(CA.RDN.rdn(subject), :cn) do
        nil -> CA.CMP.storeReply(csr,cert,CA.CMP.ref(),profile)
         cn -> case :filelib.is_regular("#{CA.CSR.dir(profile)}/#{cn}.csr") do
                    false -> CA.CMP.storeReply(csr,cert,cn,profile)
                    true -> [] end end

#     {:ok, cert} = :"PKIX1Explicit88".encode(:Certificate, CA.CMP.convertOTPtoPKIX_subj(cert))
      {:ok, certRepMsg} = :'PKIXCMP-2009'.encode(:CertRepMessage, CA.CMP.Scheme."CertRepMessage"(response: reply))

      body = :base64.encode certRepMsg
      conn |> put_resp_content_type("application/pkix-cert")
           |> put_resp_header("Content-Transfer-Encoding", "base64")
           |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
           |> resp(200, body)
           |> send_resp()
  end

  def post(conn,_,curve,_template,op) when curve in @profiles  do
      send_resp(conn, 200, CA.EST.encode(%{"curve" => curve, "operation" => op}))
  end
end
