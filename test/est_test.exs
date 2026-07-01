defmodule CA.ESTTest do
  use ExUnit.Case

  @openssl_dir Path.expand("openssl", File.cwd!())

  setup do
    key_path = Path.join(@openssl_dir, "test_est.key")
    csr_path = Path.join(@openssl_dir, "test_est.csr")
    der_path = Path.join(@openssl_dir, "test_est_der.csr")
    base64_path = Path.join(@openssl_dir, "test_est_b64.csr")

    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-est"

    # Generate a fresh EC key and a CSR (PEM)
    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)
    {_, 0} = CA.Test.OpenSSL.cmd(["req", "-new", "-key", key_path, "-out", csr_path, "-subj", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"], cd: @openssl_dir)

    pem_csr = File.read!(csr_path)
    [{:CertificationRequest, der_csr, _}] = :public_key.pem_decode(pem_csr)
    base64_csr = :base64.encode(der_csr)

    # Write the alternate formats to disk for curl to upload
    File.write!(der_path, der_csr)
    File.write!(base64_path, base64_csr)

    on_exit(fn ->
      File.rm(key_path)
      File.rm(csr_path)
      File.rm(der_path)
      File.rm(base64_path)
    end)

    {:ok, pem_path: csr_path, der_path: der_path, base64_path: base64_path, cn: cn}
  end

  defp verify_est_response!(body, cn) do
    # 1. Base64-decode the response
    cms_der = :base64.decode(body)

    # 2. ASN.1 decode ContentInfo
    {:ok, {:ContentInfo, {1, 2, 840, 113_549, 1, 7, 2}, signed_data}} =
      :"CryptographicMessageSyntax-2010".decode(:ContentInfo, cms_der)

    {:SignedData, :v1, [], {:EncapsulatedContentInfo, {1, 2, 840, 113_549, 1, 7, 1}, :asn1_NOVALUE}, certs, [], []} =
      signed_data

    # 3. Verify certificates are present
    assert length(certs) >= 2
    [{:certificate, pkix_cert} | _] = certs

    # 4. Check that we can encode/decode back to a valid certificate with the correct subject
    {:ok, cert_der} = :"PKIX1Explicit-2009".encode(:Certificate, pkix_cert)
    {:ok, otp_cert} = X509.Certificate.from_der(cert_der)

    assert inspect(X509.Certificate.subject(otp_cert)) =~ cn
  end

  defp parse_curl_response(response_text) do
    case String.split(response_text, "\r\n\r\n", parts: 2) do
      [headers, body] -> {headers, String.trim(body)}
      _ -> {"", response_text}
    end
  end

  defp est_request!(csr_path, path) do
    {response, status} =
      System.cmd("curl", [
        "-sS", "-i",
        "-X", "POST",
        "-H", "Content-Type: application/pkcs10",
        "--data-binary", "@" <> csr_path,
        "http://127.0.0.1:8047" <> path
      ], stderr_to_stdout: true)

    assert status == 0, "curl failed with status #{status}:\n#{response}"

    {headers, body} = parse_curl_response(response)
    normalized_headers = String.downcase(headers)

    assert normalized_headers =~ "http/1.1 200",
           "EST request failed. Response headers:\n#{headers}\nResponse body:\n#{body}"

    assert normalized_headers =~ "content-type: application/pkcs7-mime",
           "Unexpected EST content type. Response headers:\n#{headers}\nResponse body:\n#{body}"

    assert normalized_headers =~ "content-transfer-encoding: base64",
           "EST response is not Base64 encoded. Response headers:\n#{headers}\nResponse body:\n#{body}"

    body
  end

  test "EST simpleenroll with PEM CSR", %{pem_path: csr_path, cn: cn} do
    body = est_request!(csr_path, "/.well-known/est/simpleenroll")
    verify_est_response!(body, cn)
  end

  test "EST simpleenroll with raw DER CSR", %{der_path: der_path, cn: cn} do
    body = est_request!(der_path, "/.well-known/est/simpleenroll")
    verify_est_response!(body, cn)
  end

  test "EST simpleenroll with Base64 CSR", %{base64_path: base64_path, cn: cn} do
    body = est_request!(base64_path, "/.well-known/est/simpleenroll")
    verify_est_response!(body, cn)
  end

  test "EST simpleenroll with explicit profile in URL", %{pem_path: csr_path, cn: cn} do
    body = est_request!(csr_path, "/.well-known/est/secp384r1-client/simpleenroll")
    verify_est_response!(body, cn)
  end

  test "EST simplereenroll with PEM CSR", %{pem_path: csr_path, cn: cn} do
    body = est_request!(csr_path, "/.well-known/est/simplereenroll")
    verify_est_response!(body, cn)
  end
end
