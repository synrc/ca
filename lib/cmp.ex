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

  def baseKey(pass, salt, iter), do:
      :lists.foldl(fn _, acc ->
      :crypto.hash(:sha256, acc) end, pass <> salt,
      :lists.seq(1,iter))

  def validateProtection(header, body, code) do
      {:PKIHeader, _, _, _, _, protectionAlg, _, _, _, _, _, _, _} = header
      {_oid, salt, _owf, _mac, counter} = protection(protectionAlg)
      incomingProtection = CA."ProtectedPart"(header: header, body: body)
      {:ok, bin} = :"PKIXCMP-2009".encode(:'ProtectedPart', incomingProtection)
      verifyKey  = baseKey(:application.get_env(:ca, :pbm, "0000"), salt, counter)
      :crypto.mac(:hmac, CA.KDF.hs(:erlang.size(code)), verifyKey, bin)
  end

  def message(_socket, _header, {:ir, req}, _) do
      :lists.map(fn {:CertReqMsg, req, sig, code} ->
         :io.format 'request: ~p~n', [req]
         :io.format 'signature: ~p~n', [sig]
         :io.format 'code: ~p~n', [code]
      end, req)
  end

  def message(_socket, _header, {:genm, req} = _body, _code) do
      :io.format 'generalMessage: ~p~n', [req]
  end

  def message(socket, header, {:p10cr, csr} = body, code) do
      {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID,
         transactionID, senderNonce, _recipNonce, _freeText, _generalInfo} = header
      code = validateProtection(header, body, code)

      {ca_key, ca} = CA.CSR.read_ca()
      subject = X509.CSR.subject(csr)
      :io.format '~p~n',[subject]
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
      answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:certConf, statuses}, code) do
      {:PKIHeader, _, from, to, _, _, _, _, _, senderNonce, _, _, _} = header

      :lists.map(fn {:CertStatus,bin,no,{:PKIStatusInfo, :accepted, _, _}} ->
          :logger.info 'CERTCONF ~p request ~p~n', [no,:binary.part(bin,0,8)]
      end, statuses)

      pkibody = {:pkiconf, :asn1_NOVALUE}
      pkiheader = CA."PKIHeader"(header, sender: to, recipient: from, recipNonce: senderNonce)
      answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(_socket, _header, body, _code) do
      :logger.info 'Strange PKIMessage request ~p', [body]
  end

  def protection(:asn1_NOVALUE), do: {"","","","",1}
  def protection(protectionAlg) do
      {_,oid,{_,param}} = protectionAlg
      {:ok, parameters} = :"PKIXCMP-2009".decode(:'PBMParameter', param)
      {:PBMParameter, salt, {_,owf,_}, counter, {_,mac,_} } = parameters
      {oid, salt, owf, mac, counter}
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

  def loop(socket) do
      case :gen_tcp.recv(socket, 0) do
           {:ok, data} ->
               {{_,_headers},asn} = :asn1rt_nif.decode_ber_tlv(data)
               [_,body] = :string.split asn, "\r\n\r\n", :all
               {:ok,dec} = :'PKIXCMP-2009'.decode(:'PKIMessage', body)
               {:PKIMessage, header, body, code, _extra} = dec
               __MODULE__.message(socket, header, body, code)
               loop(socket)
          {:error, :closed} -> :exit
      end
  end
end