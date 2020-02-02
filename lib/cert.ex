defmodule KEP do
  require Record

  Record.defrecord(:certAttrs, serial: "", cn: "", givenName: "", surname: "", o: "", title: "", ou: "", c: "", locality: "")

  def extract(code, person) do
    case :lists.keyfind(code, 2, person) do
      false -> ""
      {_, _, {:printable, str}} -> str
      {_, _, {:utf8, str}} -> str
    end
  end

  def parseSignData(bin) do
    {_, {:ContentInfo, _, ci}} = :KEP.decode(:ContentInfo, bin)
    {:ok, {:SignedData, _, alg, x, c, x1, x2}} = :KEP.decode(:SignedData, ci)
    parseSignDataCert({alg,x,c,x1,x2})
  end

  def parseSignDataCert({_,_,:asn1_NOVALUE,_,_}), do: []
  def parseSignDataCert({_,_,[cert],_,_}), do: parseCert(cert)

  def parseAttrs(attrs) do
    certAttrs(
      o: extract({2, 5, 4, 10}, attrs),
      ou: extract({2, 5, 4, 11}, attrs),
      title: extract({2, 5, 4, 12}, attrs),
      cn: extract({2, 5, 4, 3}, attrs),
      givenName: extract({2, 5, 4, 42}, attrs),
      surname: extract({2, 5, 4, 4}, attrs),
      locality: extract({2, 5, 4, 7}, attrs),
      serial: extract({2, 5, 4, 5}, attrs),
      c: extract({2, 5, 4, 6}, attrs)
    )
  end

  def parseCert(cert) do
    {:Certificate, a, _, _} = cert
    {:Certificate_toBeSigned, _ver, _sel, _alg, issuer, _val, issuee, _, _, _, _} = a
    person = :lists.flatten(:erlang.element(2, issuee))
    ca = :lists.flatten(:erlang.element(2, issuer))
    {parseAttrs(person),parseAttrs(ca)}
  end
end
