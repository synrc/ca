defmodule CA.CMPTest do
  use ExUnit.Case

  @openssl_dir Path.expand("openssl", File.cwd!())

  setup do
    key_path = Path.join(@openssl_dir, "test_cmp.key")
    csr_path = Path.join(@openssl_dir, "test_cmp.csr")
    cert_path = Path.join(@openssl_dir, "test_cmp.pem")

    on_exit(fn ->
      File.rm(key_path)
      File.rm(csr_path)
      File.rm(cert_path)
    end)

    {:ok, key: key_path, csr: csr_path, cert: cert_path}
  end


  import ExUnit.CaptureLog

  test "CMP server rejects malformed DER without leaving the client waiting" do
    capture_log(fn ->
      {:ok, socket} =
        :gen_tcp.connect(~c"127.0.0.1", CA.port(:cmp), [:binary, active: false], 1_000)

      invalid_der = <<48, 3, 2, 1, 1>>

      request =
        "POST / HTTP/1.0\r\n" <>
          "Host: 127.0.0.1\r\n" <>
          "Content-Type: application/pkixcmp\r\n" <>
          "Content-Length: #{byte_size(invalid_der)}\r\n\r\n" <>
          invalid_der

      assert :ok = :gen_tcp.send(socket, request)
      assert {:ok, response} = :gen_tcp.recv(socket, 0, 1_000)
      assert response =~ "HTTP/1.0 400 Bad Request"
      assert response =~ "Malformed CMP request"
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
    end)
  end

  @tag :openssl_cmp
  test "CMP certificate enrollment (p10cr) using openssl client", %{key: key_path, csr: csr_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-cmp"

    # 1. Generate EC private key
    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    # 2. Generate PKCS#10 CSR
    {_, 0} = CA.Test.OpenSSL.cmd(["req", "-new", "-key", key_path, "-out", csr_path, "-subj", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"], cd: @openssl_dir)

    # 3. Call openssl cmp to issue the certificate
    # The server is already running under supervision on port 8829
    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "p10cr",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestp10cr",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-certout", cert_path,
        "-csr", csr_path
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0 do
      IO.puts("CMP CLIENT FAILURE:\n#{output}")
    end

    assert status == 0
    assert File.exists?(cert_path)

    {cert_info, 0} = CA.Test.OpenSSL.cmd(["x509", "-noout", "-subject", "-in", cert_path], cd: @openssl_dir)
    assert String.replace(cert_info, " ", "") =~ "CN=#{cn}"
  end
end
