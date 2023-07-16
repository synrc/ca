defmodule CSR do

  def ca() do
      ca_key = X509.PrivateKey.new_ec(:sect571r1)
      {ca_key, X509.Certificate.self_signed(ca_key,
          "/C=UA/L=Kyiv/O=SYNRC/CN=CSR-CMP", template: :root_ca)}
  end

  def server(cn) do
      {ca_key, ca} = ca()
      server_key = X509.PrivateKey.new_ec(:sect571r1)
        X509.Certificate.new(X509.PublicKey.derive(server_key),
           "/C=UA/L=Kyiv/O=SYNRC/CN=" <> cn, ca, ca_key,
           extensions: [subject_alt_name:
              X509.Certificate.Extension.subject_alt_name(["n2o.dev", "erp.uno"]) ])
  end

  def csr() do
      {ca_key, ca} = ca()
      priv = X509.PrivateKey.new_ec(:sect571r1)
      csr = X509.CSR.new(priv, "/C=UA/L=Kyiv/O=SYNRC",
            extension_request: [X509.Certificate.Extension.subject_alt_name(["n2o.dev"])])
      true = X509.CSR.valid?(csr)
      subject = X509.CSR.subject(csr)
      :io.format '~p~n', [csr]
      X509.Certificate.new(X509.CSR.public_key(csr), subject, ca, ca_key,
         extensions: [subject_alt_name:
           X509.Certificate.Extension.subject_alt_name(["n2o.dev", "erp.uno"]) ])
  end

end
