defmodule CA.NIST.PrivateKeyStorageTest do
  use ExUnit.Case

  test "NIST Private Key Storage profile provides correct OIDs" do
    assert CA.NIST.PrivateKeyStorage.controls() == [
             CA.SPE.oid(:"id-spe-sc-12"),
             CA.SPE.oid(:"id-spe-sc-12-4"),
             CA.SPE.oid(:"id-spe-sc-12-5"),
             CA.SPE.oid(:"id-spe-sc-13"),
             CA.SPE.oid(:"id-spe-sc-28"),
             CA.SPE.oid(:"id-spe-sc-28-1"),
             CA.SPE.oid(:"id-spe-mp-4"),
             CA.SPE.oid(:"id-spe-mp-6")
           ]
  end

  test "private keys are stored encrypted at rest and backward compatible" do
    profile = "secp384r1"
    cn = "maxim-#{:crypto.strong_rand_bytes(3) |> Base.encode16(case: :lower)}-nist"

    # Backup existing CA key & pem if they exist so we do not overwrite active developer keys
    ca_key_path = Path.expand("synrc/ecc/#{profile}/ca.key")
    ca_pem_path = Path.expand("synrc/ecc/#{profile}/ca.pem")

    has_backup? = File.exists?(ca_key_path)
    if has_backup? do
      File.rename!(ca_key_path, ca_key_path <> ".bak")
      File.rename!(ca_pem_path, ca_pem_path <> ".bak")
    end

    on_exit(fn ->
      # Restore backups if they were created, overwriting the test CA files.
      # If there was no backup, we do NOT delete ca.key/ca.pem so they remain in ./synrc/
      if has_backup? do
        File.rename!(ca_key_path <> ".bak", ca_key_path)
        File.rename!(ca_pem_path <> ".bak", ca_pem_path)
      end
    end)

    # 1. Generate encrypted root CA key and certificate
    {ca_key_orig, ca_cert_orig} = CA.CSR.root(profile, rdn: "/C=UA/L=Київ/O=SYNRC/CN=#{cn}")

    assert File.exists?(ca_key_path)
    ca_key_bin = File.read!(ca_key_path)

    # 2. Verify that key is encrypted on disk (cannot be read without passphrase)
    assert {:error, _} = X509.PrivateKey.from_pem(ca_key_bin)

    # 3. Verify that we can decrypt/read the CA key (which uses the config password)
    {ca_key_loaded, ca_cert_loaded} = CA.CSR.read_ca(profile)
    assert ca_key_loaded == ca_key_orig
    assert ca_cert_loaded == ca_cert_orig

    # 4. Generate client private key and verify encryption at rest
    client_key_path = Path.expand("synrc/ecc/#{profile}/#{cn}.key")
    _csr = CA.CSR.client(profile, rdn: "/C=UA/L=Київ/O=SYNRC/CN=#{cn}", cn: cn)

    assert File.exists?(client_key_path)
    client_key_bin = File.read!(client_key_path)

    # Verify client key is encrypted
    assert {:error, _} = X509.PrivateKey.from_pem(client_key_bin)

    # Verify it can be loaded with the password
    password = :application.get_env(:ca, :password, "0000")
    assert {:ok, _decoded} = X509.PrivateKey.from_pem(client_key_bin, password: password)

    # 5. Verify backward compatibility: load unencrypted PEM key
    unencrypted_key = X509.PrivateKey.new_ec(:secp384r1)
    unencrypted_pem = X509.PrivateKey.to_pem(unencrypted_key)

    # Test loading using OTP/ECDSA signing helpers
    assert CA.ECDSA.OTP.private(unencrypted_pem) == unencrypted_key
    assert CA.ECDSA.private(unencrypted_pem) == CA.ECDSA.numberFromString(:erlang.element(3, unencrypted_key))
  end
end
