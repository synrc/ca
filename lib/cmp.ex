defmodule CA.CMP do
    require CA

    # IETF 2510:2005 X.509 PKI CMP

    # openssl cmp -cmd genm -server 127.0.0.1:1829 \
    #             -recipient "/CN=CMPserver" -ref 1234 -secret pass:0000

    # openssl cmp -cmd ir -server 127.0.0.1:1829 \
    #             -path priv/certs -srvcert ca.pem -ref NewUser \
    #             -secret pass:0000 -certout maxim.pem -newkey maxim.key -subject "/CN=maxim/O=SYNRC/ST=Kyiv/C=UA"

    # openssl cmp -cmd p10cr -server localhost:1829 \
    #             -path . -srvcert ca.pem -ref cmptestp10cr \
    #             -secret pass:0000 -certout $client.pem -csr $client.csr

    def code(),         do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
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

    def mac(bin, salt, iter) do
        base_key = :lists.foldl(fn x, acc ->
            :crypto.hash(:sha256, acc) end, bin <> salt, :lists.seq(1,iter))
        :binary.part(base_key, 0, 20)
    end

    def message(socket, header, {:p10cr, csr} = body, code) do
        {:PKIHeader, pvno, from, to, messageTime, {_,oid,{_,param}} = protectionAlg, senderKID, recipKID,
           transactionID, senderNonce, recipNonce, freeText, generalInfo} = header
        {:ok, parameters} = :"PKIXCMP-2009".decode(:'PBMParameter', param)
        {:PBMParameter, salt, {_,owf,_}, counter, {_,mac,_} } = parameters
        {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
        csr2 = {:CertificationRequest, {:CertificationRequestInfo, v, subj(subj), x, y}, b, c}

        {ca_key, ca} = CA.CSR.read_ca()
        subject = X509.CSR.subject(csr)
        true = X509.CSR.valid?(csr2)
        cert = X509.Certificate.new(X509.CSR.public_key(csr), subj(subject), ca, ca_key,
           extensions: [subject_alt_name: X509.Certificate.Extension.subject_alt_name(["synrc.com"]) ])

        reply = CA."CertRepMessage"(response:
              [ CA."CertResponse"(certReqId: 1,
                certifiedKeyPair: CA."CertifiedKeyPair"(certOrEncCert:
                  {:certificate, {:x509v3PKCert, convertOTPtoPKIX(cert)}}),
                status: CA."PKIStatusInfo"(status: 0))])

        incomingProtection = CA."ProtectedPart"(header: header, body: body)
        {:ok, bin} = :"PKIXCMP-2009".encode(:'ProtectedPart', incomingProtection)
        verify1 = :crypto.pbkdf2_hmac(:sha256, bin, salt, counter, 20)
        verify2 = mac(bin, salt, counter)

        :io.format 'code: ~p~n', [code]
        :io.format 'vfy1: ~p~n', [verify1]
        :io.format 'vfy2: ~p~n', [verify2]
        :io.format 'pvno: ~p~n', [pvno]
#       :io.format 'from: ~p~n', [from]
#       :io.format 'to: ~p~n', [to]
        :io.format 'messageTime: ~p~n', [messageTime]
        :io.format 'protectionAlgortihm: ~p~n', [CA.ALG.lookup(oid)]
        :io.format 'senderKID: ~p~n', [senderKID]
        :io.format 'recipKID: ~p~n', [recipKID]
        :io.format 'transactionID: ~p~n', [transactionID]
        :io.format 'senderNonce: ~p~n', [senderNonce]
        :io.format 'recipNonce: ~p~n', [recipNonce]
        :io.format 'freeText: ~p~n', [freeText]
        :io.format 'generalInfo: ~p~n', [generalInfo]
        :io.format 'salt: ~p~n', [salt]
        :io.format 'owf: ~p~n', [CA.ALG.lookup(owf)]
        :io.format 'counter: ~p~n', [counter]
        :io.format 'mac: ~p~n', [CA.ALG.lookup(mac)]
#       :io.format 'issuedOTP: ~p~n', [cert]
#       :io.format 'issuedPKIX: ~p~n', [convertOTPtoPKIX(cert)]

        pkiheader  = CA."PKIHeader"(sender: to,
                                    recipient: from,
                                    pvno: pvno,
                                    protectionAlg: protectionAlg,
                                    messageTime: messageTime,
                                    transactionID: transactionID)
        pkibody    = {:cp, reply}
        outgoingProtection = CA."ProtectedPart"(header: pkiheader, body: pkibody)
        {:ok, out} = :"PKIXCMP-2009".encode(:'ProtectedPart', outgoingProtection)
        kdf = :crypto.pbkdf2_hmac(:sha256, out, salt, counter, 20)
#       kdf = mac(out, salt, counter)
        :io.format 'protection: ~p~n', [kdf]

        answer(socket, pkiheader, pkibody, kdf)
    end

    def answer(socket, header, body, code) do
        message = CA."PKIMessage"(header: header, body: body, protection: code)
        {:ok, bytes} = :'PKIXCMP-2009'.encode(:'PKIMessage', message)
        res =  "HTTP/1.0 200 OK\r\n"
            <> "Server: SYNRC CA\r\n"
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
#                 :io.format 'PKIMessage:~n~p~n', [dec]
                  __MODULE__.message(socket, header, body, code)
                  loop(socket)
             {:error, :closed} -> :exit
        end
    end
end