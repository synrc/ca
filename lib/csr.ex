defmodule CA.CSR do
  @moduledoc "CA/CSR library."

  def ca() do
      ca_key = X509.PrivateKey.new_ec(:secp384r1)
      dn = "/C=UA/L=Київ/O=SYNRC/CN=CA"
      :logger.info 'CSR CMP DN ~p~n', [dn]
      ca = X509.Certificate.self_signed(ca_key, dn, template: :root_ca)
      der = :public_key.der_encode(:ECPrivateKey, ca_key)
      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      :file.write_file "ca.key", pem
      :file.write_file "ca.pem", X509.Certificate.to_pem(ca)
      {ca_key, ca}
  end

  def read_ca() do
      {:ok, ca_key_bin} = :file.read_file "ca.key"
      {:ok, ca_bin} = :file.read_file "ca.pem"
      {:ok, ca_key} = X509.PrivateKey.from_pem ca_key_bin
      {:ok, ca} = X509.Certificate.from_pem ca_bin
      {ca_key, ca}
  end

  def server(name) do
      {ca_key, ca} = read_ca()
      dn = "/C=UA/L=Київ/O=SYNRC/CN=" <> name
      server_key = X509.PrivateKey.new_ec(:secp384r1)
      :logger.info 'CSR SERVER DN ~p~n', [dn]
      X509.Certificate.new(X509.PublicKey.derive(server_key),
        dn, ca, ca_key, extensions: [subject_alt_name:
          X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])
  end

  def csr(user) do
      {ca_key, ca} = read_ca()
      priv = X509.PrivateKey.new_ec(:secp384r1)
      der = :public_key.der_encode(:ECPrivateKey, priv)
      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      :file.write_file(user <> ".key", pem)
      dn = "/C=UA/L=Київ/O=SYNRC/CN=" <> user
      :logger.info 'CSR USER DN ~p~n', [dn]
      csr = X509.CSR.new(priv, dn, extension_request: [
            X509.Certificate.Extension.subject_alt_name(["synrc.com"])])
      :file.write_file(user <> ".csr", X509.CSR.to_pem(csr))
      true = X509.CSR.valid?(csr)
      subject = X509.CSR.subject(csr)
      X509.Certificate.new(X509.CSR.public_key(csr),
         subject, ca, ca_key, extensions: [subject_alt_name:
           X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])
      csr
  end

end
