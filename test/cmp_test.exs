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

  @tag :openssl_cmp
  @tag :openssl_cmp
  test "CMP certificate enrollment (ir) using openssl client", %{key: key_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-ir"

    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "ir",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestir",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-certout", cert_path,
        "-newkey", key_path,
        "-subject", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0, do: IO.puts("CMP IR FAILURE:\n#{output}")
    assert status == 0
    assert File.exists?(cert_path)
  end

  @tag :openssl_cmp
  test "CMP certificate enrollment (cr) using openssl client", %{key: key_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-cr"

    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "cr",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestcr",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-certout", cert_path,
        "-newkey", key_path,
        "-subject", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0, do: IO.puts("CMP CR FAILURE:\n#{output}")
    assert status == 0
    assert File.exists?(cert_path)
  end

  @tag :openssl_cmp
  test "CMP certificate enrollment (kur) using openssl client", %{key: key_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-kur"

    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    # First get a cert
    {_, 0} = CA.Test.OpenSSL.cmd(
      [
        "cmp", "-cmd", "ir",
        "-server", "127.0.0.1:8829", "-secret", "pass:0000",
        "-ref", "cmptestir", "-path", ".",
        "-srvcert", "synrc.pem", "-certout", cert_path,
        "-newkey", key_path, "-subject", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"
      ],
      cd: @openssl_dir
    )

    # Renew the cert
    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "kur",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestkur",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-certout", cert_path,
        "-oldcert", cert_path,
        "-newkey", key_path
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0, do: IO.puts("CMP KUR FAILURE:\n#{output}")
    assert status == 0
    assert File.exists?(cert_path)
  end

  @tag :openssl_cmp
  test "CMP certificate revocation (rr) using openssl client", %{key: key_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}-rr"

    {_, 0} = CA.Test.OpenSSL.cmd(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    # 1. Enroll
    {_, 0} = CA.Test.OpenSSL.cmd(
      [
        "cmp", "-cmd", "ir",
        "-server", "127.0.0.1:8829", "-secret", "pass:0000",
        "-ref", "cmptestir", "-path", ".",
        "-srvcert", "synrc.pem", "-certout", cert_path,
        "-newkey", key_path, "-subject", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"
      ],
      cd: @openssl_dir
    )

    # 2. Revoke using openssl cmp -cmd rr
    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "rr",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestrr",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-oldcert", cert_path
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0, do: IO.puts("CMP RR FAILURE:\n#{output}")
    assert status == 0
  end

  @tag :openssl_cmp
  test "CMP general messages (genm) using openssl client" do
    {output, status} = CA.Test.OpenSSL.cmd(
      [
        "cmp",
        "-cmd", "genm",
        "-server", "127.0.0.1:8829",
        "-secret", "pass:0000",
        "-ref", "cmptestgenm",
        "-path", ".",
        "-srvcert", "synrc.pem",
        "-infotype", "currentCRL"
      ],
      cd: @openssl_dir,
      stderr_to_stdout: true
    )

    if status != 0, do: IO.puts("CMP GENM FAILURE:\n#{output}")
    assert status == 0
  end
end
