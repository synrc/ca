defmodule CA.EST.Post do
  @moduledoc "CA/EST POST Method HTTP handlers."
  @profiles ["secp256k1", "secp384r1", "secp521r1"]
  @classes ["ca", "ra", "server", "client", "human", "program"]

  import Plug.Conn
  require CA
  require CA.CMP
  require CA.CMP.Scheme

  def post(conn, "CA", profile, template, "PKCS-10") when profile in @profiles and template in @classes do
    {ca_key, ca} = CA.CSR.read_ca(profile)
    {:ok, body, _} = Plug.Conn.read_body(conn, [])
    bin = :base64.decode(:binary.part(body, 35, byte_size(body) - 68))
    {:ok, csr} = :"PKCS-10".decode(:CertificationRequest, bin)

    true = profile == CA.RDN.profile(csr)
    subject = X509.CSR.subject(csr)

    :logger.info(~c"HTTP P10CR from ~tp template ~tp profile ~p~n", [CA.RDN.rdn(subject), template, CA.RDN.profile(csr)])

    true = X509.CSR.valid?(CA.RDN.encodeAttrsCSR(csr))

    cert =
      X509.Certificate.new(X509.CSR.public_key(csr), CA.RDN.encodeAttrs(subject), ca, ca_key,
        extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"])]
      )

    reply =
      case Keyword.get(CA.RDN.rdn(subject), :cn) do
        nil ->
          CA.CMP.storeReply(csr, cert, CA.CMP.ref(), profile)

        cn ->
          case :filelib.is_regular("#{CA.CSR.dir(profile)}/#{cn}.csr") do
            false -> CA.CMP.storeReply(csr, cert, cn, profile)
            true -> []
          end
      end

    #     {:ok, cert} = :"PKIX1Explicit88".encode(:Certificate, CA.CMP.convertOTPtoPKIX_subj(cert))
    {:ok, certRepMsg} = :"PKIXCMP-2009".encode(:CertRepMessage, CA.CMP.Scheme."CertRepMessage"(response: reply))

    body = :base64.encode(certRepMsg)

    conn
    |> put_resp_content_type("application/pkix-cert")
    |> put_resp_header("Content-Transfer-Encoding", "base64")
    |> put_resp_header("Content-Length", Integer.to_string(byte_size(body)))
    |> resp(200, body)
    |> send_resp()
  end

  def parse_csr(body) do
    case :public_key.pem_decode(body) do
      [{:CertificationRequest, bin, _} | _] ->
        :"PKCS-10".decode(:CertificationRequest, bin)
      _ ->
        case :"PKCS-10".decode(:CertificationRequest, body) do
          {:ok, csr} ->
            {:ok, csr}
          _ ->
            try do
              clean_body = String.replace(body, ~r/\s+/, "")
              decoded = :base64.decode(clean_body)
              :"PKCS-10".decode(:CertificationRequest, decoded)
            rescue
              _ -> {:error, :invalid_csr}
            end
        end
    end
  end

  defp try_valid_csr(csr) do
    try do
      X509.CSR.valid?(csr)
    rescue
      _ -> false
    catch
      _ -> false
    end
  end

  def post(conn, "CA", curve, template, op) when op in ["ENROLL", "RE-ENROLL"] do
    {:ok, body, _} = Plug.Conn.read_body(conn, [])

    case parse_csr(body) do
      {:ok, csr} ->
        curve_name = if curve in @profiles, do: curve, else: CA.RDN.profile(csr)
        template_name = if template in @classes, do: template, else: "client"

        if curve_name in @profiles do
          {ca_key, ca} = CA.CSR.read_ca(curve_name)
          subject = CA.RDN.decodeAttrs(X509.CSR.subject(csr))

          # Robust CSR verification: support raw CSR signature or attribute-encoded CSR signature
          is_valid = try_valid_csr(csr) || try_valid_csr(CA.RDN.encodeAttrsCSR(csr))

          if is_valid do
            cert =
              X509.Certificate.new(
                X509.CSR.public_key(csr),
                subject,
                ca,
                ca_key,
                extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"])]
              )

            cn =
              case Keyword.get(CA.RDN.rdn(subject), :cn) do
                nil -> CA.CMP.ref()
                val -> val
              end

            CA.CMP.storeReply(csr, cert, cn, curve_name)

            der_ca = :public_key.pkix_encode(:OTPCertificate, ca, :otp)
            {:ok, pkix_ca} = :"PKIX1Explicit-2009".decode(:Certificate, der_ca)

            der_cert = :public_key.pkix_encode(:OTPCertificate, cert, :otp)
            {:ok, pkix_cert} = :"PKIX1Explicit-2009".decode(:Certificate, der_cert)

            ci =
              {:ContentInfo, {1, 2, 840, 113_549, 1, 7, 2},
               {:SignedData, :v1, [],
                {:EncapsulatedContentInfo, {1, 2, 840, 113_549, 1, 7, 1}, :asn1_NOVALUE},
                [{:certificate, pkix_cert}, {:certificate, pkix_ca}], [], []}}

            {:ok, cms} = :"CryptographicMessageSyntax-2010".encode(:ContentInfo, ci)
            resp_body = :base64.encode(cms)

            conn
            |> put_resp_content_type("application/pkcs7-mime")
            |> put_resp_header("Content-Transfer-Encoding", "base64")
            |> put_resp_header("Content-Length", Integer.to_string(byte_size(resp_body)))
            |> resp(200, resp_body)
            |> send_resp()
          else
            send_resp(conn, 400, "CSR signature verification failed")
          end
        else
          send_resp(conn, 400, "Unsupported curve: #{inspect(curve_name)}")
        end

      {:error, _reason} ->
        send_resp(conn, 400, "Invalid CSR")
    end
  end

  def post(conn, _, curve, _template, op) when curve in @profiles do
    send_resp(conn, 200, CA.EST.encode(%{"curve" => curve, "operation" => op}))
  end
end
