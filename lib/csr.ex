defmodule CA.CSR do

  def ca() do
      ca_key = X509.PrivateKey.new_ec(:secp384r1)
      ca = X509.Certificate.self_signed(ca_key,
            "/C=UA/L=Kyiv/O=SYNRC/CN=CSR-CMP", template: :root_ca)
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

  def server(cn) do
      {ca_key, ca} = read_ca()
      server_key = X509.PrivateKey.new_ec(:secp384r1)
        X509.Certificate.new(X509.PublicKey.derive(server_key),
           "/C=UA/L=Kyiv/O=SYNRC/CN=" <> cn, ca, ca_key,
           extensions: [subject_alt_name:
              X509.Certificate.Extension.subject_alt_name(["n2o.dev", "erp.uno"]) ])
  end

  def csr() do
      {ca_key, ca} = read_ca()
      priv = X509.PrivateKey.new_ec(:secp384r1)
      csr = X509.CSR.new(priv, "/C=UA/L=Kyiv/O=SYNRC",
            extension_request: [X509.Certificate.Extension.subject_alt_name(["n2o.dev"])])
      :io.format 'CSR: ~p~n', [csr]
      :file.write_file "maxim.csr", X509.CSR.to_pem(csr)
      true = X509.CSR.valid?(csr)
      subject = X509.CSR.subject(csr)
      :io.format 'Subject ~p~n', [subject]
      :io.format 'CSR ~p~n', [csr]
      X509.Certificate.new(X509.CSR.public_key(csr), subject, ca, ca_key,
         extensions: [subject_alt_name:
           X509.Certificate.Extension.subject_alt_name(["n2o.dev", "erp.uno"]) ])
      csr
  end

end
