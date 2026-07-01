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

  test "CMP certificate enrollment (p10cr) using openssl client", %{key: key_path, csr: csr_path, cert: cert_path} do
    cn = "maxim-#{:crypto.strong_rand_bytes(3) |> Base.encode16(case: :lower)}"

    on_exit(fn ->
      File.rm(Path.expand("synrc/ecc/secp384r1/#{cn}.csr"))
      File.rm(Path.expand("synrc/ecc/secp384r1/#{cn}.cer"))
    end)

    # 1. Generate EC private key
    {_, 0} = System.cmd("openssl", ["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key_path], cd: @openssl_dir)

    # 2. Generate PKCS#10 CSR
    {_, 0} = System.cmd("openssl", ["req", "-new", "-key", key_path, "-out", csr_path, "-subj", "/C=UA/ST=Kyiv/O=SYNRC/CN=#{cn}"], cd: @openssl_dir)

    # 3. Call openssl cmp to issue the certificate
    # The server is already running under supervision on port 8829
    {output, status} = System.cmd(
      "openssl",
      [
        "cmp",
        "-cmd", "p10cr",
        "-server", "localhost:8829",
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

    # 4. Verify the issued certificate contains the correct subject
    {cert_info, 0} = System.cmd("openssl", ["x509", "-noout", "-subject", "-in", cert_path], cd: @openssl_dir)
    assert cert_info =~ "CN=#{cn}"
  end
end
