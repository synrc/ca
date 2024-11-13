defmodule CA.CSR do
  @moduledoc "CA/CSR library."

  def ca           do   root("secp384r1", [rdn: "/C=UA/L=Київ/O=SYNRC/CN=CA"]) end
  def server(name) do server("secp384r1", [rdn: "/C=UA/L=Київ/O=SYNRC/CN=#{name}", cn: "#{name}"]) end
  def client(name) do client("secp384r1", [rdn: "/C=UA/L=Київ/O=SYNRC/CN=#{name}", cn: "#{name}"]) end
  def dir(profile) do "synrc/ecc/#{profile}/" end

  def root(profile, [rdn: rdn]) do
      :filelib.ensure_dir dir(profile)
      ca_key = X509.PrivateKey.new_ec(:erlang.binary_to_atom(profile))
      :logger.info 'CSR CMP DN ~p~n', [rdn]
      ca = X509.Certificate.self_signed(ca_key, rdn, template:  %X509.Certificate.Template{
        validity: round(25 * 365.2425), # 25 years
        hash: :sha256,
        extensions: [
          basic_constraints: X509.Certificate.Extension.basic_constraints(true, 1),
          key_usage: X509.Certificate.Extension.key_usage([:digitalSignature, :keyCertSign, :cRLSign]),
          subject_key_identifier: true,
          authority_key_identifier: true
        ]
      })
      der = :public_key.der_encode(:ECPrivateKey, ca_key)
      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      :file.write_file "#{dir(profile)}/ca.key", pem
      :file.write_file "#{dir(profile)}/ca.pem", X509.Certificate.to_pem(ca)
      {ca_key, ca}
  end

  def server(profile, [rdn: rdn, cn: user]) do
      {ca_key, ca} = read_ca(profile)
      :filelib.ensure_dir dir(profile)
      priv = X509.PrivateKey.new_ec(:erlang.binary_to_atom(profile))
      der = :public_key.der_encode(:ECPrivateKey, priv)
      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      :file.write_file("#{dir(profile)}/#{user}.key", pem)
      :logger.info 'CSR SERVER DN ~p~n', [rdn]
      csr = X509.CSR.new(priv, rdn, extension_request: [
            X509.Certificate.Extension.subject_alt_name(["synrc.com"])])
      :file.write_file("#{dir(profile)}/#{user}.csr", X509.CSR.to_pem(csr))
      true = X509.CSR.valid?(csr)
      subject = X509.CSR.subject(csr)
      server = X509.Certificate.new(X509.CSR.public_key(csr),
         subject, ca, ca_key, extensions: [subject_alt_name:
           X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])
      :file.write_file "#{dir(profile)}/#{user}.cer", X509.Certificate.to_pem(server)
      csr
  end

  def client(profile, [rdn: rdn, cn: user]) do
      priv = X509.PrivateKey.new_ec(:erlang.binary_to_atom(profile))
      der = :public_key.der_encode(:ECPrivateKey, priv)
      pem = :public_key.pem_encode([{:ECPrivateKey, der, :not_encrypted}])
      :file.write_file("#{dir(profile)}/#{user}.key", pem)
      :logger.info 'CSR CLIENT DN ~p~n', [rdn]
      csr = X509.CSR.new(priv, rdn, extension_request: [
            X509.Certificate.Extension.subject_alt_name(["synrc.com"])])
      :file.write_file("#{dir(profile)}/#{user}.csr", X509.CSR.to_pem(csr))
      csr
  end

  def init(profile) do
      case :filelib.is_regular("#{CA.CSR.dir(profile)}/ca.key") do
           false -> root(profile, [rdn: "/C=UA/L=Київ/O=SYNRC/CN=CA"])
           true -> []
      end
  end

  def read_ca(profile) do
      init(profile)
      {:ok, ca_key_bin} = :file.read_file "#{CA.CSR.dir(profile)}/ca.key"
      {:ok, ca_bin} = :file.read_file "#{CA.CSR.dir(profile)}/ca.pem"
      {:ok, ca_key} = X509.PrivateKey.from_pem ca_key_bin
      {:ok, ca} = X509.Certificate.from_pem ca_bin
      {ca_key, ca}
  end

  def read_ca_public(profile) do
      init(profile)
      {:ok, ca_bin} = :file.read_file "#{CA.CSR.dir(profile)}/ca.pem"
      {:ok, ca} = X509.Certificate.from_pem ca_bin
#     {:ok, bin} = :"PKIX1Explicit-2009".encode(:Certificate, CA.RDN.convertOTPtoPKIX(ca))
      {:ok, bin} = :"PKIX1Explicit88".encode(:Certificate, CA.RDN.convertOTPtoPKIX_subj(ca))
      bin
  end

end
