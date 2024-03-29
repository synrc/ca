defmodule CA do
  @moduledoc """
  The main CA module mostly contains (except OTP application prelude)
  public_key and PKIXCMP HRL definitions. The latter are generated
  from PKIXCMP-2009.asn1 the ASN.1 specification of CMP protocol.
  """
  use Application
  use Supervisor

  require Record
  Enum.each(Record.extract_all(from_lib: "ca/include/PKIXCMP-2009.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)

  Enum.each(Record.extract_all(from_lib: "public_key/include/public_key.hrl"),
            fn {name, definition} -> Record.defrecord(name, definition) end)

  def init([]), do: {:ok, { {:one_for_one, 5, 10}, []} }
  def start(_type, _args) do
      :logger.add_handlers(:ca)
      CA.CMP.start
      CA.CMC.start
      CA.TSP.start
      CA.OCSP.start
      :supervisor.start_link({:local, __MODULE__}, __MODULE__, [])
  end

  def parseSubj(csr) do
      {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
      {:CertificationRequest, {:CertificationRequestInfo, v, CA.CAdES.subj(subj), x, y}, b, c}
  end

  def convertOTPtoPKIX(cert) do
      {:Certificate,{:TBSCertificate,:v3,a,ai,rdn,v,rdn2,{p1,{p21,p22,_pki},p3},b,c,ext},ai,code} =
         :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
      {:Certificate,{:TBSCertificate,:v3,a,ai,CA.CAdES.unsubj(rdn),v,CA.CAdES.unsubj(rdn2),
           {p1,{p21,p22,{:namedCurve,{1,3,132,0,34}}},p3},b,c,ext},ai,code}
  end

end
