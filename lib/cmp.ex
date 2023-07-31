defmodule CA.CMP do
    @moduledoc "CA/CMP TCP server."
    require CA

    def code(),  do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
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

    def subj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn [{t,oid,{:uTF8String,x}}] -> [{t,oid,:asn1rt_nif.encode_ber_tlv({12, :erlang.iolist_to_binary(x)})}]
                                     [{t,oid,x}] when is_list(x) -> [{t,oid,:asn1rt_nif.encode_ber_tlv({19, :erlang.iolist_to_binary(x)})}]
                                     [{t,oid,x}] -> [{t,oid,x}] end, attrs)}
    end

    def unsubj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn [{t,oid,x}] -> case :asn1rt_nif.decode_ber_tlv(x) do
                                         {{12,a},_} -> [{t,oid,{:uTF8String,a}}]
                                         {{19,a},_} -> [{t,oid,:erlang.binary_to_list(a)}]
                                     end end, attrs)}
    end

    def convertOTPtoPKIX(cert) do
        {:Certificate,{:TBSCertificate,:v3,a,ai,rdn,v,rdn2,{p1,{p21,p22,pki},p3},b,c,ext},ai,code} =
           :public_key.pkix_decode_cert(:public_key.pkix_encode(:OTPCertificate, cert, :otp), :plain)
        {:Certificate,{:TBSCertificate,:v3,a,ai,unsubj(rdn),v,unsubj(rdn2),{p1,{p21,p22,{:namedCurve,{1,3,132,0,34}}},p3},b,c,ext},ai,code}
    end

    def baseKey(pass, salt, iter), do: :lists.foldl(fn _, acc -> :crypto.hash(:sha256, acc) end, pass <> salt, :lists.seq(1,iter))

    def parseSubj(csr) do
        {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
        {:CertificationRequest, {:CertificationRequestInfo, v, subj(subj), x, y}, b, c}
    end

    def validateProtection(header, body, code) do
        {:PKIHeader, pvno, from, to, messageTime, {_,oid,{_,param}} = protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header
        {oid, salt, owf, mac, counter} = protection(protectionAlg)
        incomingProtection = CA."ProtectedPart"(header: header, body: body)
        {:ok, bin} = :"PKIXCMP-2009".encode(:'ProtectedPart', incomingProtection)
        verifyKey  = baseKey(:application.get_env(:ca, :pbm, "0000"), salt, counter)
        :crypto.mac(:hmac, CA.KDF.hs(:erlang.size(code)), verifyKey, bin)
    end

    def message(socket, header, {:ir, req} = body, code) do
        {:PKIHeader, pvno, from, to, messageTime, {_,oid,{_,param}} = protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header
        :lists.map(fn {:CertReqMsg, req, sig, code} ->
           :io.format 'request: ~p~n', [req]
           :io.format 'signature: ~p~n', [sig]
           :io.format 'code: ~p~n', [code]
        end, req)
    end

    def message(socket, header, {:genm, req} = body, code) do
        {:PKIHeader, pvno, from, to, messageTime, {_,oid,{_,param}} = protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header
        {:ok, parameters} = :"PKIXCMP-2009".decode(:'PBMParameter', param)
        {:PBMParameter, salt, {_,owf,_}, counter, {_,mac,_} } = parameters
        :io.format 'generalMessage: ~p~n', [req]
    end

    def message(socket, header, {:p10cr, csr} = body, code) do
        {:PKIHeader, pvno, from, to, messageTime, protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header
        code = validateProtection(header, body, code)

        {ca_key, ca} = CA.CSR.read_ca()
        subject = X509.CSR.subject(csr)
        true = X509.CSR.valid?(parseSubj(csr))
        cert = X509.Certificate.new(X509.CSR.public_key(csr), subj(subject), ca, ca_key,
           extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

        reply = CA."CertRepMessage"(response:
              [ CA."CertResponse"(certReqId: 0,
                certifiedKeyPair: CA."CertifiedKeyPair"(certOrEncCert:
                  {:certificate, {:x509v3PKCert, convertOTPtoPKIX(cert)}}),
                status: CA."PKIStatusInfo"(status: 1))])

#       :io.format 'issuedOTP: ~p~n', [cert]

        pkibody = {:cp, reply}
        pkiheader = CA."PKIHeader"(sender: to, recipient: from, pvno: pvno, recipNonce: senderNonce,
            transactionID: transactionID, protectionAlg: protectionAlg, messageTime: messageTime)
        answer(socket, pkiheader, pkibody, validateProtection(pkiheader, pkibody, code))
    end

#       :io.format 'issuedOTP: ~p~n', [cert]
#       :io.format 'issuedPKIX: ~p~n', [convertOTPtoPKIX(cert)]

    def message(socket, header, {:certConf, statuses} = body, code) do
        {:PKIHeader, pvno, from, to, messageTime, {_,oid,{_,param}} = protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header

        :lists.map(fn {:CertStatus,bin,no,{:PKIStatusInfo, :accepted, _, _}} -> 
            :io.format 'CERTCONF ~p request ~p~n', [no,:binary.part(bin,0,8)]
        end, statuses)

        pkibody = {:pkiconf, :asn1_NOVALUE}
        pkiheader = CA."PKIHeader"(sender: to, recipient: from, pvno: pvno, recipNonce: senderNonce,
            transactionID: transactionID, protectionAlg: protectionAlg, messageTime: messageTime)
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
        send = :gen_tcp.send(socket, res)
    end

    def loop(socket) do
        case :gen_tcp.recv(socket, 0) do
             {:ok, data} ->
                  {{_,headers},asn} = :asn1rt_nif.decode_ber_tlv(data)
                  [_,body] = :string.split asn, "\r\n\r\n", :all
                  {:ok,dec} = :'PKIXCMP-2009'.decode(:'PKIMessage', body)
                  {:PKIMessage, header, body, code, extra} = dec
                  __MODULE__.message(socket, header, body, code)
                  loop(socket)
             {:error, :closed} -> :exit
        end
    end
end