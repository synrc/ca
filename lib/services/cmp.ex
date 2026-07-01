defmodule CA.CMP do
  @moduledoc "CA/CMP TCP server."

  require CA
  require CA.CMP.Scheme
  require Logger

  # Authority PKI X.509 CMP over TCP RFC 4210 9480 9481

  # [1] https://datatracker.ietf.org/doc/html/rfc4210
  # [2] https://datatracker.ietf.org/doc/html/rfc9480

  def ref() do
    to_string(:lists.filter(fn x -> true == x > 44 and x < 59 end, :erlang.ref_to_list(:erlang.make_ref())))
  end

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
    :logger.info(~c"Running CA.CMP with Authority 5.11.15 at 0.0.0.0:~p (tcp)", [port])
    {:ok, socket} = :gen_tcp.listen(port, [:binary, {:active, false}, {:reuseaddr, true}])
    accept(socket)
  end

  def accept(socket) do
    {:ok, fd} = :gen_tcp.accept(socket)
    {:ok, _pid} = Task.Supervisor.start_child(CA.TaskSupervisor, fn -> loop(fd, []) end, restart: :temporary)
    accept(socket)
  end

  def loop(socket, ca) do
    case :gen_tcp.recv(socket, 0) do
      {:error, _} ->
        :exit

      {:ok, stage1} ->
        try do
          [_headers | body] = :string.split(stage1, "\r\n\r\n", :all)

          case body do
            [""] ->
              case :gen_tcp.recv(socket, 0) do
                {:error, _} -> :exit
                {:ok, stage2} -> handleMessage(socket, stage2)
              end

            _ ->
              handleMessage(socket, body)
          end

          __MODULE__.loop(socket, ca)
        catch
          _ ->
            __MODULE__.loop(socket, ca)
        end
    end
  end

  def handleMessage(socket, body) do
    binary_body = IO.iodata_to_binary(body)

    case :"PKIXCMP-2009".decode(:PKIMessage, binary_body) do
      {:ok, {:PKIMessage, header, body, code, _extra}} ->
        __MODULE__.message(socket, header, body, code)

      {:error, reason} ->
        Logger.info("Malformed CMP request: #{inspect(reason)}, body: #{inspect(binary_body)}")
        bad_request(socket, "Malformed CMP request")
        {:error, {:invalid_pki_message, reason}}
    end
  end

  defp bad_request(socket, message) do
    body = message <> "\n"

    response =
      "HTTP/1.0 400 Bad Request\r\n" <>
        "Server: SYNRC CA/CMP\r\n" <>
        "Content-Length: #{byte_size(body)}\r\n" <>
        "Content-Type: text/plain; charset=utf-8\r\n" <>
        "Connection: close\r\n\r\n" <>
        body

    _ = :gen_tcp.send(socket, response)
    :gen_tcp.close(socket)
  end

  def baseKey(pass, salt, iter, owf \\ :sha256),
    do:
      :lists.foldl(
        fn _, acc ->
          :crypto.hash(owf, acc)
        end,
        pass <> salt,
        :lists.seq(1, iter)
      )

  def protection(:asn1_NOVALUE), do: {"", "", "", "", 1}

  def protection(protectionAlg) do
    {_, oid, {_, param}} = protectionAlg
    {:ok, parameters} = :"PKIXCMP-2009".decode(:PBMParameter, param)
    {:PBMParameter, salt, {_, owf, _}, counter, {_, mac, _}} = parameters
    {oid, salt, owf, mac, counter}
  end

  def clean_for_encode(term) do
    case term do
      {:InfoTypeAndValue, type, value} ->
        {:InfoTypeAndValue, type, clean_open_type(value)}
      list when is_list(list) -> Enum.map(list, &clean_for_encode/1)
      tuple when is_tuple(tuple) ->
        tuple
        |> Tuple.to_list()
        |> Enum.map(&clean_for_encode/1)
        |> List.to_tuple()
      other -> other
    end
  end

  def clean_open_type(term) do
    case term do
      {:namedCurve, {1, 3, 132, 0, 34}} -> <<6, 5, 43, 129, 4, 0, 34>>
      {:namedCurve, {1, 3, 132, 0, 10}} -> <<6, 5, 43, 129, 4, 0, 10>>
      {:namedCurve, {1, 3, 132, 0, 35}} -> <<6, 5, 43, 129, 4, 0, 35>>
      [namedCurve: oid] -> clean_open_type({:namedCurve, oid})
      list when is_list(list) -> Enum.map(list, &clean_open_type/1)
      tuple when is_tuple(tuple) ->
        tuple
        |> Tuple.to_list()
        |> Enum.map(&clean_open_type/1)
        |> List.to_tuple()
      other -> other
    end
  end

  def validateProtection(header, body, code) do
    {:PKIHeader, _, _, _, _, protectionAlg, _, _, _, _, _, _, _} = header
    {oid, salt, owfoid, macoid, counter} = protection(protectionAlg)

    case CA.ALG.lookup(oid) do
      {:"id-PasswordBasedMac", _} ->
        clean_body = clean_for_encode(body)
        incomingProtection = CA.CMP.Scheme."ProtectedPart"(header: header, body: clean_body)
        {:ok, bin} = :"PKIXCMP-2009".encode(:ProtectedPart, incomingProtection)
        # SHA-2
        {owf, _} = CA.ALG.lookup(owfoid)
        # DH shared secret
        pbm = :application.get_env(:ca, :pbm, "0000")
        verifyKey = baseKey(pbm, salt, counter, owf)
        :logger.info(~c"TCP counter ~p~n", [counter])
        hash = CA.KDF.hs(:erlang.size(code))

        res =
          case CA.ALG.lookup(macoid) do
            {:"hMAC-SHA1", _} -> :crypto.mac(:hmac, hash, verifyKey, bin)
            _ -> :crypto.mac(:hmac, hash, verifyKey, bin)
          end

        :logger.info(~c"TCP validateProtection ~p~n", [res])
        res

      {_, _} ->
        ""
    end
  end

  def answer(socket, header, body, code) do
    message = CA.CMP.Scheme."PKIMessage"(header: header, body: body, protection: code)
    {:ok, bytes} = :"PKIXCMP-2009".encode(:PKIMessage, message)
    :logger.info(~c"TCP answer ~p~n", [message])
    bin = :erlang.iolist_to_binary(bytes)

    res =
      "HTTP/1.0 200 OK\r\n" <>
        "Server: SYNRC CA/CMP\r\n" <>
        "Content-Length: #{byte_size(bin)}\r\n" <>
        "Content-Type: application/pkixcmp\r\n\r\n" <>
        bin

    :gen_tcp.send(socket, res)
  end

  def storeReply(csr, cert, cn, profile, certReqId \\ -1) do
    {:ok, _} = :"PKCS-10".encode(:CertificationRequest, csr)
    :file.write_file("#{CA.CSR.dir(profile)}/#{cn}.csr", X509.CSR.to_pem(csr))
    :file.write_file("#{CA.CSR.dir(profile)}/#{cn}.cer", X509.Certificate.to_pem(cert))
    cert = :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)

    [
      CA.CMP.Scheme."CertResponse"(
        certReqId: certReqId,
        certifiedKeyPair: CA.CMP.Scheme."CertifiedKeyPair"(certOrEncCert: {:certificate, {:x509v3PKCert, cert}}),
        status: CA.CMP.Scheme."PKIStatusInfo"(status: 0)
      )
    ]
  end

  def message(socket, header, {:ir, req} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    true = code == val_prot

    # ir matches curve from profile or falls back
    profile = case req do
      [{:CertReqMsg, cert_req, _, _} | _] ->
        cert_template = elem(cert_req, 2)
        pubkey_info = elem(cert_template, 7)
        profile_from_pubkey(pubkey_info)
      _ -> "secp384r1"
    end

    reply = process_cert_reqs(req, profile)
    pkibody = {:ip, CA.CMP.Scheme."CertRepMessage"(response: reply)}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:cr, req} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    true = code == val_prot

    profile = case req do
      [{:CertReqMsg, cert_req, _, _} | _] ->
        cert_template = elem(cert_req, 2)
        pubkey_info = elem(cert_template, 7)
        profile_from_pubkey(pubkey_info)
      _ -> "secp384r1"
    end

    reply = process_cert_reqs(req, profile)
    pkibody = {:cp, CA.CMP.Scheme."CertRepMessage"(response: reply)}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:kur, req} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    true = code == val_prot

    profile = case req do
      [{:CertReqMsg, cert_req, _, _} | _] ->
        cert_template = elem(cert_req, 2)
        pubkey_info = elem(cert_template, 7)
        profile_from_pubkey(pubkey_info)
      _ -> "secp384r1"
    end

    reply = process_cert_reqs(req, profile)
    pkibody = {:kup, CA.CMP.Scheme."CertRepMessage"(response: reply)}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:rr, req} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    true = code == val_prot
    profile = "secp384r1"

    statuses =
      Enum.map(req, fn {:RevDetails, cert_details, _crl_entry} ->
        serial =
          case elem(cert_details, 2) do
            :asn1_NOVALUE -> nil
            {:asn1_OutmostTag, s} -> s
            s when is_integer(s) -> s
            _ -> nil
          end

        if serial do
          CA.EST.CRL.revoke(profile, serial)
          CA.CMP.Scheme."PKIStatusInfo"(status: 0)
        else
          CA.CMP.Scheme."PKIStatusInfo"(status: 2, statusString: [~c"Missing serial number"])
        end
      end)

    pkibody = {:rp, CA.CMP.Scheme."RevRepContent"(status: statuses)}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:genm, req} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    true = code == val_prot

    responses =
      Enum.map(req, fn {:InfoTypeAndValue, info_type, _info_val} ->
        case info_type do
          {1, 3, 6, 1, 5, 5, 7, 4, 17} ->
            ca_der = CA.CSR.read_ca_public("secp384r1")
            {:InfoTypeAndValue, info_type, {:asn1_OPENTYPE, ca_der}}

          {1, 3, 6, 1, 5, 5, 7, 4, 18} ->
            ca_der = CA.CSR.read_ca_public("secp384r1")
            {:InfoTypeAndValue, info_type, {:asn1_OPENTYPE, ca_der}}

          {1, 3, 6, 1, 5, 5, 7, 4, 19} ->
            crl_der = CA.EST.CRL.generate("secp384r1")
            {:InfoTypeAndValue, info_type, {:asn1_OPENTYPE, crl_der}}

          _ ->
            {:InfoTypeAndValue, info_type, :asn1_NOVALUE}
        end
      end)

    pkibody = {:genp, responses}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def process_cert_reqs(req_list, profile) do
    Enum.map(req_list, fn {:CertReqMsg, cert_req, _pop, _reg_info} ->
      cert_req_id = elem(cert_req, 1)
      cert_template = elem(cert_req, 2)
      subject_rdn = elem(cert_template, 6)
      subject = CA.RDN.decodeAttrs(subject_rdn)

      pubkey_info = elem(cert_template, 7)

      {ca_key, ca} = CA.CSR.read_ca(profile)

      {:ok, der_pub} = :"PKIX1Explicit-2009".encode(:SubjectPublicKeyInfo, pubkey_info)
      {:ok, public_key} = X509.PublicKey.from_der(der_pub)

      cert =
        X509.Certificate.new(
          public_key,
          subject,
          ca,
          ca_key,
          extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"])]
        )

      cn =
        case Keyword.get(CA.RDN.rdn(subject), :cn) do
          nil -> ref()
          val -> val
        end

      storeReplyCert(cert, cn, profile, cert_req_id)
    end)
    |> List.flatten()
  end

  def storeReplyCert(cert, cn, profile, certReqId) do
    :file.write_file("#{CA.CSR.dir(profile)}/#{cn}.cer", X509.Certificate.to_pem(cert))
    cert_otp = :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)

    [
      CA.CMP.Scheme."CertResponse"(
        certReqId: certReqId,
        certifiedKeyPair: CA.CMP.Scheme."CertifiedKeyPair"(certOrEncCert: {:certificate, {:x509v3PKCert, cert_otp}}),
        status: CA.CMP.Scheme."PKIStatusInfo"(status: 0)
      )
    ]
  end

  def profile_from_pubkey({:SubjectPublicKeyInfo, {:AlgorithmIdentifier, {1, 2, 840, 10045, 2, 1}, {:asn1_OPENTYPE, x}}, _}) do
    {{6, oid}, _} = :asn1rt_nif.decode_ber_tlv(x)
    {alg, _} = CA.ALG.lookup(:oid.decode(oid))
    "#{alg}"
  end
  def profile_from_pubkey(_), do: "secp384r1"

  def message(socket, header, {:p10cr, csr} = body, code) do
    {:PKIHeader, pvno, from, to, messageTime, protectionAlg, _senderKID, _recipKID, transactionID, senderNonce,
     _recipNonce, _freeText, _generalInfo} = header

    val_prot = validateProtection(header, body, code)
    :io.format(~c"DEBUG: Code size: ~p, ValProt size: ~p~n", [:erlang.size(code), :erlang.size(val_prot)])
    :io.format(~c"DEBUG: Code: ~p~nValProt: ~p~n", [code, val_prot])
    true = code == val_prot
    profile = CA.RDN.profile(csr)
    {ca_key, ca} = CA.CSR.read_ca(profile)
    subject = CA.RDN.decodeAttrs(X509.CSR.subject(csr))
    true = X509.CSR.valid?(csr)
    public_key = X509.CSR.public_key(csr)

    cert =
      X509.Certificate.new(public_key, subject, ca, ca_key,
        extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"])]
      )

    #      :io.format 'X509 Subj ~tw~n', [subject]
    #      :io.format 'X509 Key ~tw~n', [public_key]
    #      :io.format 'X509 CA ~tw~n', [ca]
    #      :io.format 'X509 CA Key ~tw~n', [ca_key]
    #      :io.format 'X509 Extensions ~tw~n', [[subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ]]
    #      :io.format 'X509 Client Certificate Generated ~tw~n', [cert]

    reply =
      case Keyword.get(CA.RDN.rdn(subject), :cn) do
        nil ->
          storeReply(csr, cert, ref(), profile)

        cn ->
          case :filelib.is_regular("#{CA.CSR.dir(profile)}/#{cn}.csr") do
            false -> storeReply(csr, cert, cn, profile)
            true -> []
          end
      end

    pkibody = {:cp, CA.CMP.Scheme."CertRepMessage"(response: reply)}

    pkiheader =
      CA.CMP.Scheme."PKIHeader"(
        sender: to,
        recipient: from,
        pvno: pvno,
        recipNonce: senderNonce,
        transactionID: transactionID,
        protectionAlg: protectionAlg,
        messageTime: messageTime
      )

    :logger.info(~c"TCP P10CR request ~p~n", [csr])

    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(socket, header, {:certConf, statuses}, code) do
    {:PKIHeader, _, from, to, _, _, _, _, _, senderNonce, _, _, _} = header

    :lists.map(
      fn {:CertStatus, bin, no, {:PKIStatusInfo, :accepted, _, _}} ->
        :logger.info(~c"TCP CERTCONF ~p request ~p~n", [no, :base64.encode(bin)])
      end,
      statuses
    )

    pkibody = {:pkiconf, :asn1_NOVALUE}
    pkiheader = CA.CMP.Scheme."PKIHeader"(header, sender: to, recipient: from, recipNonce: senderNonce)
    :ok = answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
  end

  def message(_socket, _header, body, _code) do
    :logger.info(~c"Strange PKIMessage request ~p", [body])
  end

  # WSL Service
  # netsh interface portproxy add v4tov4 listenport=8829 listenaddress=192.168.0.3 connectport=8829 connectaddress=172.31.45.170
  # netsh interface portproxy add v4tov4 listenport=8047 listenaddress=192.168.0.3 connectport=8047 connectaddress=172.31.45.170
  # New-NetFireWallRule -DisplayName 'CMP-OUT' -Direction Outbound -LocalPort 8829 -Action Allow -Protocol TCP
  # New-NetFireWallRule -DisplayName 'CMP-IN'  -Direction Inbound  -LocalPort 8829 -Action Allow -Protocol TCP
  # New-NetFireWallRule -DisplayName 'EST-OUT' -Direction Outbound -LocalPort 8047 -Action Allow -Protocol TCP
  # New-NetFireWallRule -DisplayName 'EST-IN'  -Direction Inbound  -LocalPort 8047 -Action Allow -Protocol TCP
end
