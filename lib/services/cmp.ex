defmodule CA.CMP do
  @moduledoc "CA/CMP TCP server."
  require CA

# WSL Service
# netsh interface portproxy add v4tov4 listenport=8829 listenaddress=192.168.0.3 connectport=8829 connectaddress=172.31.45.170
# netsh interface portproxy add v4tov4 listenport=8047 listenaddress=192.168.0.3 connectport=8047 connectaddress=172.31.45.170
# New-NetFireWallRule -DisplayName 'CMP-OUT' -Direction Outbound -LocalPort 8829 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'CMP-IN'  -Direction Inbound  -LocalPort 8829 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'EST-OUT' -Direction Outbound -LocalPort 8047 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'EST-IN'  -Direction Inbound  -LocalPort 8047 -Action Allow -Protocol TCP

  def parseSubj(csr) do
      {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
      {:CertificationRequest, {:CertificationRequestInfo, v, CA.CRT.subj(subj), x, y}, b, c}
  end

  def convertOTPtoPKIX(cert) do
      {:Certificate,{:TBSCertificate,:v3,a,ai,rdn,v,rdn2,{p1,{p21,p22,_pki},p3},b,c,ext},ai,code} =
         :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
      {:Certificate,{:TBSCertificate,:v3,a,ai,CA.CRT.unsubj(rdn),v,CA.CRT.unsubj(rdn2),
           {p1,{p21,p22,{:namedCurve,{1,3,132,0,34}}},p3},b,c,ext},ai,code}
  end

  def start(), do: {:ok, :erlang.spawn(fn -> listen(8829) end)}

  def listen(port) do
      {:ok, socket} = :gen_tcp.listen(port, [:binary, {:active, false}, {:reuseaddr, true}])
      accept(socket)
  end

  def accept(socket) do
      {:ok, fd} = :gen_tcp.accept(socket)
      :erlang.spawn(fn ->
            # Read CA here
            ca = []
            __MODULE__.loop(fd,ca)
      end)
      accept(socket)
  end

  def loop(socket,ca) do
      case :gen_tcp.recv(socket, 0) do
           {:error, :closed} -> :exit
           {:ok, stage1} ->
               try do
                 [_headers|body] = :string.split stage1, "\r\n\r\n", :all
                 case body do
                    [""] -> case :gen_tcp.recv(socket, 0) do
                                 {:error, :closed} -> :exit
                                 {:ok, stage2} -> handleMessage(socket,stage2) end
                       _ -> handleMessage(socket,body)
                 end
                 loop(socket,ca)
               catch _ ->
                 loop(socket,ca)
               end
      end
  end

  def handleMessage(socket,body) do
      {:ok,dec} = :'PKIXCMP-2009'.decode(:'PKIMessage', body)
      {:PKIMessage, header, body, code, _extra} = dec
      __MODULE__.message(socket, header, body, code)
  end

  def baseKey(pass, salt, iter, owf \\ :sha256), do:
      :lists.foldl(fn _, acc ->
      :crypto.hash(owf, acc) end, pass <> salt,
      :lists.seq(1,iter))

  def protection(:asn1_NOVALUE), do: {"","","","",1}
  def protection(protectionAlg) do
      {_,oid,{_,param}} = protectionAlg
      {:ok, parameters} = :"PKIXCMP-2009".decode(:'PBMParameter', param)
      {:PBMParameter, salt, {_,owf,_}, counter, {_,mac,_} } = parameters
      {oid, salt, owf, mac, counter}
  end

  def validateProtection(header, body, code) do
      {:PKIHeader, _, _, _, _, protectionAlg, _, _, _, _, _, _, _} = header
      {oid, salt, owfoid, macoid, counter} = protection(protectionAlg)
      case CA.ALG.lookup(oid) do
           {:'id-PasswordBasedMac', _ } ->
                incomingProtection = CA."ProtectedPart"(header: header, body: body)
                {:ok, bin} = :"PKIXCMP-2009".encode(:'ProtectedPart', incomingProtection)
                {owf,_} = CA.ALG.lookup(owfoid) # SHA-2
                pbm = :application.get_env(:ca, :pbm, "0000") # DH shared secret
                verifyKey  = baseKey(pbm, salt, counter, owf)
                hash = CA.KDF.hs(:erlang.size(code))
                case CA.ALG.lookup(macoid) do
                     {:'hMAC-SHA1',_} -> :crypto.mac(:hmac, hash, verifyKey, bin)
                     _ -> :crypto.mac(:hmac, hash, verifyKey, bin)
                end
           {_, _ } ->
                ""
      end
  end

  def answer(socket, header, body, code) do
      message = CA."PKIMessage"(header: header, body: body, protection: code)
      {:ok, bytes} = :'PKIXCMP-2009'.encode(:'PKIMessage', message)
      res =  "HTTP/1.0 200 OK\r\n"
          <> "Server: SYNRC CA/CMP\r\n"
          <> "Content-Type: application/pkixcmp\r\n\r\n"
          <> :erlang.iolist_to_binary(bytes)
      :gen_tcp.send(socket, res)
  end

  def message(_socket, _header, {:ir, req}, _) do
      :lists.map(fn {:CertReqMsg, req, sig, code} ->
         :logger.info 'request: ~p ~p ~p~n', [req,sig,code]
      end, req)
  end

  def message(_socket, _header, {:genm, req} = _body, _code) do
      :io.format 'generalMessage: ~p~n', [req]
  end

  def message(socket, header, {:p10cr, csr} = body, code) do
      {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID,
         transactionID, senderNonce, _recipNonce, _freeText, _generalInfo} = header
      true = code == validateProtection(header, body, code)

      {ca_key, ca} = CA.CSR.read_ca()
      subject = X509.CSR.subject(csr)
      :logger.info 'P10CR ~tp~n', [CA.CRT.rdn(subject)]
      true = X509.CSR.valid?(parseSubj(csr))
      cert = X509.Certificate.new(X509.CSR.public_key(csr), CA.CRT.subj(subject), ca, ca_key,
         extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

      reply = CA."CertRepMessage"(response:
            [ CA."CertResponse"(certReqId: 0,
              certifiedKeyPair: CA."CertifiedKeyPair"(certOrEncCert:
                {:certificate, {:x509v3PKCert, convertOTPtoPKIX(cert)}}),
              status: CA."PKIStatusInfo"(status: 0))])

      pkibody = {:cp, reply}
      pkiheader = CA."PKIHeader"(sender: to, recipient: from, pvno: pvno, recipNonce: senderNonce,
          transactionID: transactionID, protectionAlg: protectionAlg, messageTime: messageTime)

      :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
      :logger.info 'CP ~p~n', [senderNonce]
  end

  def message(socket, header, {:certConf, statuses}, code) do
      {:PKIHeader, _, from, to, _, _, _, _, _, senderNonce, _, _, _} = header

      :lists.map(fn {:CertStatus,bin,no,{:PKIStatusInfo, :accepted, _, _}} ->
          :logger.info 'CERTCONF ~p request ~p~n', [no,:binary.part(bin,0,8)]
      end, statuses)

      pkibody = {:pkiconf, :asn1_NOVALUE}
      pkiheader = CA."PKIHeader"(header, sender: to, recipient: from, recipNonce: senderNonce)
      :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
      :logger.info 'PKICONF ~p~n', [senderNonce]

  end

  def message(_socket, _header, body, _code) do
      :logger.info 'Strange PKIMessage request ~p', [body]
  end

end