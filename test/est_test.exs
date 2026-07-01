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

  defp est_get!(path, expected_content_type) do
    {response, status} =
      System.cmd("curl", [
        "-sS", "-i",
        "-X", "GET",
        "http://127.0.0.1:8047" <> path
      ], stderr_to_stdout: true)

    assert status == 0, "GET failed: #{response}"
    {headers, body} = parse_curl_response(response)
    normalized_headers = String.downcase(headers)

    assert normalized_headers =~ "http/1.1 200", "Headers: #{headers}"
    assert normalized_headers =~ "content-type: #{expected_content_type}", "Headers: #{headers}"
    body
  end

  test "EST GET operations (cacerts, csrattrs, template, root, crl)", %{cn: _cn} do
    # 1. GET ca/cacerts
    ca_pem = est_get!("/.well-known/est/ca", "application/pkix-cert")
    assert ca_pem != ""

    ca_cms = est_get!("/.well-known/est/cacerts", "application/pkcs7-mime")
    assert ca_cms != ""

    # 2. GET csrattrs / template
    attrs = est_get!("/.well-known/est/csrattrs", "application/csrattrs")
    assert attrs != ""

    template = est_get!("/.well-known/est/getcertreqtemplate", "application/csrattrs")
    assert template == attrs

    # 3. GET root update
    root = est_get!("/.well-known/est/getrootupdate", "application/pkcs7-mime")
    assert root != ""

    # 4. GET CRL
    crl_b64 = est_get!("/.well-known/est/getcrls", "application/pkcs7-crl")
    der_crl = :base64.decode(crl_b64)
    {:CertificateList, _, _, _} = :public_key.der_decode(:CertificateList, der_crl)
  end

  test "EST POST operation aliases (ir, cr, kur)", %{pem_path: csr_path, cn: cn} do
    # ir maps to ENROLL
    body = est_request!(csr_path, "/.well-known/est/initialization")
    verify_est_response!(body, cn)

    # cr maps to ENROLL
    body = est_request!(csr_path, "/.well-known/est/certification")
    verify_est_response!(body, cn)

    # kur maps to RE-ENROLL
    body = est_request!(csr_path, "/.well-known/est/keyupdate")
    verify_est_response!(body, cn)
  end

  test "EST serverkeygen generates private key and certificate", %{pem_path: csr_path, cn: _cn} do
    {response, status} =
      System.cmd("curl", [
        "-sS", "-i",
        "-X", "POST",
        "-H", "Content-Type: application/pkcs10",
        "--data-binary", "@" <> csr_path,
        "http://127.0.0.1:8047/.well-known/est/serverkeygen"
      ], stderr_to_stdout: true)

    assert status == 0
    {headers, body} = parse_curl_response(response)
    normalized_headers = String.downcase(headers)

    assert normalized_headers =~ "http/1.1 200"
    assert normalized_headers =~ "content-type: multipart/mixed; boundary=estserverkeygenboundary"

    assert body =~ "Content-Type: application/pkcs8"
    assert body =~ "Content-Type: application/pkcs7-mime; smime-type=certs-only"
  end

  test "EST revocation registers revoked certificate and updates CRL" do
    # Revoke serial number 998877
    {response, status} =
      System.cmd("curl", [
        "-sS", "-i",
        "-X", "POST",
        "--data-binary", "998877",
        "http://127.0.0.1:8047/.well-known/est/revocation"
      ], stderr_to_stdout: true)

    assert status == 0
    {headers, body} = parse_curl_response(response)
    assert headers =~ "200"
    assert body =~ "Revoked successfully"

    # Verify that the generated CRL now contains the revoked serial number
    crl_b64 = est_get!("/.well-known/est/getcrls", "application/pkcs7-crl")
    der_crl = :base64.decode(crl_b64)
    crl_struct = :public_key.der_decode(:CertificateList, der_crl)

    # toBeSigned is the TBSCertList record
    # element 7 is revokedCertificates
    tbs = elem(crl_struct, 1)
    revoked = elem(tbs, 6) # index 6 of TBSCertList record (0-indexed: tag is 0, version 1, sig 2, issuer 3, thisUpdate 4, nextUpdate 5, revokedCertificates 6)
    assert is_list(revoked)

    # Check for serial number 998877
    has_serial = Enum.any?(revoked, fn entry ->
      elem(entry, 1) == 998877 # index 1 of TBSCertList_revokedCertificates_SEQOF is userCertificate
    end)
    assert has_serial
  end
end
