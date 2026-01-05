defmodule CA.CMP do
  @moduledoc "CA/CMP TCP server."

  require CA
  require CA.CMP.Scheme
  require Logger

  # Authority PKI X.509 CMP over TCP RFC 4210 9480 9481

  # [1] https://datatracker.ietf.org/doc/html/rfc4210
  # [2] https://datatracker.ietf.org/doc/html/rfc9480

  def ref() do to_string(:lists.filter(fn x -> true == x > 44 and x < 59 end, :erlang.ref_to_list(:erlang.make_ref()))) end

  def start_link(port: port), do: {:ok, :erlang.spawn_link(fn -> listen(port) end)}
  def child_spec(opt) do
      %{
        id: CMP,
        start: {CA.CMP, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent,
        shutdown: 500
      }
  end

  def listen(port) do
      :logger.info ~c"Running CA.CMP with Authority 5.11.15 at 0.0.0.0:~p (tcp)", [port]
      {:ok, socket} = :gen_tcp.listen(port, [:binary, {:active, false}, {:reuseaddr, true}])
      accept(socket)
  end

  def accept(socket) do
      {:ok, fd} = :gen_tcp.accept(socket)
      {:ok, _pid} = Task.Supervisor.start_child(CA.TaskSupervisor, fn -> loop(fd,[]) end, restart: :temporary)
#      :erlang.spawn(fn -> ca = [] ; __MODULE__.loop(fd,ca) end)
      accept(socket)
  end

  def loop(socket,ca) do
      case :gen_tcp.recv(socket, 0) do
           {:error, _} -> :exit
           {:ok, stage1} ->
               try do
                 [_headers|body] = :string.split stage1, "\r\n\r\n", :all
                 case body do
                    [""] -> case :gen_tcp.recv(socket, 0) do
                                 {:error, _} -> :exit
                                 {:ok, stage2} -> handleMessage(socket,stage2) end
                       _ -> handleMessage(socket,body)
                 end
                 __MODULE__.loop(socket,ca)
               catch _ ->
                 __MODULE__.loop(socket,ca)
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
                incomingProtection = CA.CMP.Scheme."ProtectedPart"(header: header, body: body)
                {:ok, bin} = :"PKIXCMP-2009".encode(:'ProtectedPart', incomingProtection)
                {owf,_} = CA.ALG.lookup(owfoid) # SHA-2
                pbm = :application.get_env(:ca, :pbm, "0000") # DH shared secret
                verifyKey  = baseKey(pbm, salt, counter, owf)
                :logger.info ~c"TCP counter ~p~n", [counter]
                hash = CA.KDF.hs(:erlang.size(code))
                res = case CA.ALG.lookup(macoid) do
                     {:'hMAC-SHA1',_} -> :crypto.mac(:hmac, hash, verifyKey, bin)
                     _ -> :crypto.mac(:hmac, hash, verifyKey, bin)
                end
                :logger.info ~c"TCP validateProtection ~p~n", [res]
                res
           {_, _ } ->
                ""
      end
  end

  def answer(socket, header, body, code) do
      message = CA.CMP.Scheme."PKIMessage"(header: header, body: body, protection: code)
      {:ok, bytes} = :'PKIXCMP-2009'.encode(:'PKIMessage', message)
      :logger.info ~c"TCP answer ~p~n", [message]
      bin = :erlang.iolist_to_binary(bytes)
      res =  "HTTP/1.0 200 OK\r\n"
          <> "Server: SYNRC CA/CMP\r\n"
          <> "Content-Length: #{byte_size(bin)}\r\n"
          <> "Content-Type: application/pkixcmp\r\n\r\n"
          <> bin
      :gen_tcp.send(socket, res)
  end

  def storeReply(csr, cert, cn, profile) do
      {:ok, _} = :"PKCS-10".encode(:CertificationRequest, csr)
      :file.write_file("#{CA.CSR.dir(profile)}/#{cn}.csr", X509.CSR.to_pem(csr))
      :file.write_file("#{CA.CSR.dir(profile)}/#{cn}.cer", X509.Certificate.to_pem(cert))
      cert = :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
      [ CA.CMP.Scheme."CertResponse"(certReqId: 0,
          certifiedKeyPair: CA.CMP.Scheme."CertifiedKeyPair"(certOrEncCert:
             {:certificate, {:x509v3PKCert, cert}}),
                 status: CA.CMP.Scheme."PKIStatusInfo"(status: 0))
      ]
  end

  def message(_socket, _header, {:ir, req}, _) do
      :lists.map(fn {:CertReqMsg, req, sig, code} ->
         :logger.info ~c"request: ~p ~p ~p~n", [req,sig,code]
      end, req)
  end

  def message(_socket, _header, {:genm, req} = _body, _code) do
      :io.format ~c"generalMessage: ~p~n", [req]
  end

  def message(socket, header, {:p10cr, csr} = body, code) do
      {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID,
         transactionID, senderNonce, _recipNonce, _freeText, _generalInfo} = header
      val_prot = validateProtection(header, body, code)
      :io.format ~c"DEBUG: Code size: ~p, ValProt size: ~p~n", [:erlang.size(code), :erlang.size(val_prot)]
      :io.format ~c"DEBUG: Code: ~p~nValProt: ~p~n", [code, val_prot]
      true = code == val_prot
      profile = CA.RDN.profile(csr)
      {ca_key, ca} = CA.CSR.read_ca(profile)
      subject = CA.RDN.decodeAttrs(X509.CSR.subject(csr))
      true = X509.CSR.valid?(csr)
      public_key = X509.CSR.public_key(csr)
      cert = X509.Certificate.new(public_key, subject, ca, ca_key,
         extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

#      :io.format 'X509 Subj ~tw~n', [subject]
#      :io.format 'X509 Key ~tw~n', [public_key]
#      :io.format 'X509 CA ~tw~n', [ca]
#      :io.format 'X509 CA Key ~tw~n', [ca_key]
#      :io.format 'X509 Extensions ~tw~n', [[subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ]]
#      :io.format 'X509 Client Certificate Generated ~tw~n', [cert]

      reply = case Keyword.get(CA.RDN.rdn(subject), :cn) do
        nil -> storeReply(csr,cert,ref(),profile)
        cn -> case :filelib.is_regular("#{CA.CSR.dir(profile)}/#{cn}.csr") do
                   false -> storeReply(csr,cert,cn,profile)
                   true -> storeReply(csr,cert,cn,profile) end end # in prod return [] # no user

      pkibody = {:cp, CA.CMP.Scheme."CertRepMessage"(response: reply)}
      pkiheader = CA.CMP.Scheme."PKIHeader"(sender: to, recipient: from,
          pvno: pvno, recipNonce: senderNonce,
          transactionID: transactionID, protectionAlg: protectionAlg,
          messageTime: messageTime)
      :logger.info ~c"TCP P10CR request ~p~n", [csr]

      :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:certConf, statuses}, code) do
      {:PKIHeader, _, from, to, _, _, _, _, _, senderNonce, _, _, _} = header

      :lists.map(fn {:CertStatus,bin,no,{:PKIStatusInfo, :accepted, _, _}} ->
          :logger.info ~c"TCP CERTCONF ~p request ~p~n", [no,:base64.encode(bin)]
      end, statuses)

      pkibody = {:pkiconf, :asn1_NOVALUE}
      pkiheader = CA.CMP.Scheme."PKIHeader"(header, sender: to, recipient: from, recipNonce: senderNonce)
      :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(_socket, _header, body, _code) do
      :logger.info ~c"Strange PKIMessage request ~p", [body]
  end

# WSL Service
# netsh interface portproxy add v4tov4 listenport=8829 listenaddress=192.168.0.3 connectport=8829 connectaddress=172.31.45.170
# netsh interface portproxy add v4tov4 listenport=8047 listenaddress=192.168.0.3 connectport=8047 connectaddress=172.31.45.170
# New-NetFireWallRule -DisplayName 'CMP-OUT' -Direction Outbound -LocalPort 8829 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'CMP-IN'  -Direction Inbound  -LocalPort 8829 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'EST-OUT' -Direction Outbound -LocalPort 8047 -Action Allow -Protocol TCP
# New-NetFireWallRule -DisplayName 'EST-IN'  -Direction Inbound  -LocalPort 8047 -Action Allow -Protocol TCP

end
