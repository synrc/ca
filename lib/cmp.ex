defmodule CA.CMP do
  @moduledoc "CA/CMP TCP server."
  require CA

  def start(), do: :erlang.spawn(fn -> listen(1829) end)

  def listen(port) do
      {:ok, socket} = :gen_tcp.listen(port,
        [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
      accept(socket)
  end

  def accept(socket) do
      {:ok, fd} = :gen_tcp.accept(socket)
      :erlang.spawn(fn -> __MODULE__.loop(fd) end)
      accept(socket)
  end

  def loop(socket) do
      case :gen_tcp.recv(socket, 0) do
           {:ok, data} ->
               [_headers,body] = :string.split data, "\r\n\r\n", :all
               {:ok,dec} = :'PKIXCMP-2009'.decode(:'PKIMessage', body)
               {:PKIMessage, header, body, code, _extra} = dec
               __MODULE__.message(socket, header, body, code)
               loop(socket)
          {:error, :closed} -> :exit
      end
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
      {:PKIHeader, pvno, from, to, messageTime, protectionAlg, senderKID, _recipKID,
         transactionID, senderNonce, _recipNonce, _freeText, _generalInfo} = header
      true = code == validateProtection(header, body, code)
      :logger.info 'P10CR ~p~n', [senderKID]

      {ca_key, ca} = CA.CSR.read_ca()
      subject = X509.CSR.subject(csr)
      true = X509.CSR.valid?(CA.parseSubj(csr))
      cert = X509.Certificate.new(X509.CSR.public_key(csr), CA.CAdES.subj(subject), ca, ca_key,
         extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

      reply = CA."CertRepMessage"(response:
            [ CA."CertResponse"(certReqId: 0,
              certifiedKeyPair: CA."CertifiedKeyPair"(certOrEncCert:
                {:certificate, {:x509v3PKCert, CA.convertOTPtoPKIX(cert)}}),
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