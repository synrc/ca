defmodule CA.EST.CRL do
  @moduledoc "EST CRL generation and management."
  require Record

  Record.defrecord(:r_TBSCertList, :TBSCertList, Record.extract(:TBSCertList, from_lib: "public_key/include/public_key.hrl"))
  Record.defrecord(:r_TBSCertList_revokedCertificates_SEQOF, :TBSCertList_revokedCertificates_SEQOF, Record.extract(:TBSCertList_revokedCertificates_SEQOF, from_lib: "public_key/include/public_key.hrl"))
  Record.defrecord(:r_CertificateList, :CertificateList, Record.extract(:CertificateList, from_lib: "public_key/include/public_key.hrl"))

  def revoked_file(profile) do
    "#{CA.CSR.dir(profile)}/revoked.txt"
  end

  def read_revoked(profile) do
    file = revoked_file(profile)
    case File.read(file) do
      {:ok, content} ->
        content
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.filter(&(&1 != ""))
        |> Enum.map(&String.to_integer/1)
      {:error, _} ->
        []
    end
  end

  def revoke(profile, serial_number) do
    file = revoked_file(profile)
    File.mkdir_p!(Path.dirname(file))
    File.write!(file, "#{serial_number}\n", [:append])
    :ok
  end

  def generate(profile) do
    {ca_key, ca} = CA.CSR.read_ca(profile)
    issuer = CA.RDN.encodeAttrs(elem(elem(ca, 1), 4))

    {sig_oid, digest} = sig_alg_and_digest(profile)
    sig_alg = {:AlgorithmIdentifier, sig_oid, :asn1_NOVALUE}

    # Generate dates (thisUpdate and nextUpdate, e.g. nextUpdate 7 days in future)
    now = DateTime.utc_now()
    next_week = DateTime.add(now, 7 * 24 * 60 * 60, :second)

    this_update_val = format_time(now)
    next_update_val = format_time(next_week)

    revoked_list =
      read_revoked(profile)
      |> Enum.map(fn serial ->
        r_TBSCertList_revokedCertificates_SEQOF(
          userCertificate: serial,
          revocationDate: this_update_val,
          crlEntryExtensions: :asn1_NOVALUE
        )
      end)

    revoked_field =
      case revoked_list do
        [] -> :asn1_NOVALUE
        list -> list
      end

    tbs = r_TBSCertList(
      version: 1, # v2
      signature: sig_alg,
      issuer: issuer,
      thisUpdate: this_update_val,
      nextUpdate: next_update_val,
      revokedCertificates: revoked_field,
      crlExtensions: :asn1_NOVALUE
    )

    der_tbs = :public_key.der_encode(:TBSCertList, tbs)
    signature = :public_key.sign(der_tbs, digest, ca_key)

    cert_list = r_CertificateList(
      tbsCertList: tbs,
      signatureAlgorithm: sig_alg,
      signature: signature
    )

    :public_key.der_encode(:CertificateList, cert_list)
  end

  def sig_alg_and_digest("secp256k1"), do: {{1, 2, 840, 10045, 4, 3, 2}, :sha256}
  def sig_alg_and_digest("secp384r1"), do: {{1, 2, 840, 10045, 4, 3, 3}, :sha384}
  def sig_alg_and_digest("secp521r1"), do: {{1, 2, 840, 10045, 4, 3, 4}, :sha512}
  def sig_alg_and_digest(_), do: {{1, 2, 840, 10045, 4, 3, 3}, :sha384} # fallback

  defp format_time(dt) do
    year = rem(dt.year, 100) |> Integer.to_string() |> String.pad_leading(2, "0")
    month = dt.month |> Integer.to_string() |> String.pad_leading(2, "0")
    day = dt.day |> Integer.to_string() |> String.pad_leading(2, "0")
    hour = dt.hour |> Integer.to_string() |> String.pad_leading(2, "0")
    minute = dt.minute |> Integer.to_string() |> String.pad_leading(2, "0")
    second = dt.second |> Integer.to_string() |> String.pad_leading(2, "0")
    {:utcTime, String.to_charlist("#{year}#{month}#{day}#{hour}#{minute}#{second}Z")}
  end
end
