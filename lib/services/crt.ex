defmodule CA.CRT do
  @moduledoc "X.509 Certificates."

  def baseLength(oid) when is_tuple(oid) do CA.Curve.getLength(CA.KnownCurves.getCurveByOid(oid)) end
  def baseLength(_) do 256 end

  def decodePointFromPublic(agreement,params,publicKey) do
      bin = :binary.part(publicKey,1,:erlang.size(publicKey)-1)
      baseLength = baseLength(params)
      xs = :binary.part(bin, 0, baseLength)
      ys = :binary.part(bin, baseLength, :erlang.size(bin) - baseLength)
      [ x: CA.ECDSA.numberFromString(xs),
        y: CA.ECDSA.numberFromString(ys),
        scheme: CA.AT.oid(agreement),
        curve: CA.AT.oid(params),
      ]
  end

  def decodePublicKey(agreement,{:asn1_OPENTYPE, params},publicKey) do decodePublicKey(agreement,params,publicKey) end
  def decodePublicKey(agreement,params,publicKey) do
      case agreement do
           {1,2,840,113549,1,1,1} -> # RSA
                {:ok, key} = :"PKCS-1".decode(:'RSAPublicKey', publicKey)
                [key: key, scheme: :RSA]
           {1,2,840,10045,2,1} -> # ECDSA
                params = CA.EST.decodeObjectIdentifier(params)
                decodePointFromPublic(agreement,params,publicKey)
           {1,2,804,2,1,1,1,1,3,1,1} -> # ДСТУ-4145, ДСТУ-7564
                {:ok,p} = :DSTU.decode(:DSTU4145Params, params)
                [key: publicKey, scheme: CA.AT.oid(agreement), field: p]
           _ -> :io.format 'new publicKey agreement scheme detected: ~p~n', [agreement]
                :base64.encode publicKey
      end
  end

  def parseCertPEM(file)  do {:ok, bin} = :file.read_file file ; list = :public_key.pem_decode(bin) ; :lists.map(fn x -> parseCert(:public_key.pem_entry_decode(x)) end, list) end
  def parseCertB64(file)  do {:ok, bin} = :file.read_file file ; parseCertBin(:base64.decode(bin)) end
  def parseCertFile(file) do {:ok, bin} = :file.read_file file ; parseCertBin(bin) end
# def parseCertBin(bin)   do {:ok, cert} = :"AuthenticationFramework".decode(:Certificate, bin) ; parseCert(cert) end
  def parseCertBin(bin)   do {:ok, cert} = :"PKIX1Explicit88".decode(:Certificate, bin) ; parseCert(cert) end

  def parseCert(cert, _) do parseCert(cert) end
  def parseCert({:certificate, cert}) do parseCert(cert) end
  def parseCert(cert) do
      {:Certificate, tbs, _, _} = case cert do
         {:Certificate, tbs, x, y} -> {:Certificate, tbs, x, y}
         {:Certificate, tbs, x, y, _} -> {:Certificate, tbs, x, y}
      end

      {_, ver, serial, {_,alg,_}, issuer, {_,{_,nb},{_,na}}, issuee,
         {:SubjectPublicKeyInfo, {_, agreement, params}, publicKey}, _b, _c, exts} = tbs
      extensions = :lists.map(fn {:Extension,code,_x,b} ->
         CA.CE.oid(code, :lists.flatten(CA.CE.flat(code,:asn1rt_nif.decode_ber_tlv(b),[])))
      end, exts)
      [ resourceType: :Certificate,
        version: ver,
        signatureAlgorithm: CA.AT.code(alg),
        subject: CA.RDN.rdn(CA.RDN.decodeAttrs(issuee)),
        issuer:  CA.RDN.rdn(CA.RDN.decodeAttrs(issuer)),
        serial: :base64.encode(CA.EST.integer(serial)),
        validity: [from: nb, to: na],
        publicKey: decodePublicKey(agreement, params, publicKey),
        extensions: extensions
      ]
  end

end
