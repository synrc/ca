defmodule CA.ESTTest do
  use ExUnit.Case

  @openssl_dir Path.expand("openssl", File.cwd!())

  setup do
    key_path = Path.join(@openssl_dir, "test_est.key")
    csr_path = Path.join(@openssl_dir, "test_est.csr")
    der_path = Path.join(@openssl_dir, "test_est_der.csr")
    base64_path = Path.join(@openssl_dir, "test_est_b64.csr")

    cn = "maxim_est_#{System.system_time(:nanosecond)}"

    # Generate a fresh EC key and a CSR (PEM)
    {_, 0} = System.cmd("openssl", ["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)
    {_, 0} = System.cmd("openssl", ["req", "-new", "-key", key_path, "-out", csr_path, "-subj", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"], cd: @openssl_dir)

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
      File.rm(Path.expand("synrc/ecc/secp384r1/#{cn}.csr"))
      File.rm(Path.expand("synrc/ecc/secp384r1/#{cn}.cer"))
    end)

    {:ok, pem_path: csr_path, der_path: der_path, base64_path: base64_path}
  end

  defp verify_est_response!(body) do
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

    assert inspect(X509.Certificate.subject(otp_cert)) =~ "maxim_est"
  end

  defp parse_curl_response(response_text) do
    case String.split(response_text, "\r\n\r\n", parts: 2) do
      [headers, body] -> {headers, String.trim(body)}
      _ -> {"", response_text}
    end
  end

  test "EST simpleenroll with PEM CSR", %{pem_path: csr_path} do
    # Call curl with headers and body
    {res, 0} = System.cmd("curl", [
      "-s", "-i",
      "-X", "POST",
      "-H", "Content-Type: application/pkcs10",
      "--data-binary", "@" <> csr_path,
      "http://localhost:8047/.well-known/est/simpleenroll"
    ])

    {headers, body} = parse_curl_response(res)

    assert String.downcase(headers) =~ "content-type: application/pkcs7-mime"
    assert String.downcase(headers) =~ "content-transfer-encoding: base64"

    verify_est_response!(body)
  end

  test "EST simpleenroll with raw DER CSR", %{der_path: der_path} do
    {res, 0} = System.cmd("curl", [
      "-s", "-i",
      "-X", "POST",
      "-H", "Content-Type: application/pkcs10",
      "--data-binary", "@" <> der_path,
      "http://localhost:8047/.well-known/est/simpleenroll"
    ])

    {_headers, body} = parse_curl_response(res)
    verify_est_response!(body)
  end

  test "EST simpleenroll with Base64 CSR", %{base64_path: base64_path} do
    {res, 0} = System.cmd("curl", [
      "-s", "-i",
      "-X", "POST",
      "-H", "Content-Type: application/pkcs10",
      "--data-binary", "@" <> base64_path,
      "http://localhost:8047/.well-known/est/simpleenroll"
    ])

    {_headers, body} = parse_curl_response(res)
    verify_est_response!(body)
  end

  test "EST simpleenroll with explicit profile in URL", %{pem_path: csr_path} do
    {res, 0} = System.cmd("curl", [
      "-s", "-i",
      "-X", "POST",
      "-H", "Content-Type: application/pkcs10",
      "--data-binary", "@" <> csr_path,
      "http://localhost:8047/.well-known/est/secp384r1-client/simpleenroll"
    ])

    {_headers, body} = parse_curl_response(res)
    verify_est_response!(body)
  end

  test "EST simplereenroll with PEM CSR", %{pem_path: csr_path} do
    {res, 0} = System.cmd("curl", [
      "-s", "-i",
      "-X", "POST",
      "-H", "Content-Type: application/pkcs10",
      "--data-binary", "@" <> csr_path,
      "http://localhost:8047/.well-known/est/simplereenroll"
    ])

    {_headers, body} = parse_curl_response(res)
    verify_est_response!(body)
  end
end
