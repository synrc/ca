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
        :erlang.spawn(fn -> loop(fd) end)
        accept(socket)
    end

    def subj({:rdnSequence, attrs}) do
        {:rdnSequence, :lists.map(fn [{t,oid,{:uTF8String,x}}] -> [{t,oid,:asn1rt_nif.encode_ber_tlv({12, :erlang.iolist_to_binary(x)})}]
                                     [{t,oid,x}] when is_list(x) -> [{t,oid,:asn1rt_nif.encode_ber_tlv({19, :erlang.iolist_to_binary(x)})}]
                                     [{t,oid,x}] -> [{t,oid,x}] end, attrs)}
    end

    def unsubj({:rdnSequence, attrs}) do
        :io.format '~p~n', [attrs]
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

    def message(socket, header, {:p10cr, csr}, code) do
        {:CertificationRequest, {:CertificationRequestInfo, v, subj, x, y}, b, c} = csr
        csr2 = {:CertificationRequest, {:CertificationRequestInfo, v, subj(subj), x, y}, b, c}
        {ca_key, ca} = CA.CSR.read_ca()
        subject = X509.CSR.subject(csr)
#        :logger.info 'CA: ~p~n', [convertOTPtoPKIX(ca)]
#        :logger.info 'CSR 2: ~p~n', [csr2]
        true = X509.CSR.valid?(csr2)
#        :logger.info 'Subject: ~p~n', [subj(subject)]
#        :logger.info 'Piblic Derive: ~p~n', [X509.CSR.public_key(csr2)]
        cert = X509.Certificate.new(X509.CSR.public_key(csr), subj(subject), ca, ca_key,
         extensions: [subject_alt_name:
           X509.Certificate.Extension.subject_alt_name(["n2o.dev", "synrc.com"]) ])
        :io.format 'Issued Cert OTP: ~p~n', [cert]
        pkix = convertOTPtoPKIX(cert)
        :io.format 'Issued Cert PKIX: ~p~n', [pkix]
        body = CA."CertRepMessage"(response:
               [CA."CertResponse"(certReqId: 1,
                   certifiedKeyPair: CA."CertifiedKeyPair"(certOrEncCert: {:certificate,{:x509v3PKCert,pkix}}),
                   status: CA."PKIStatusInfo"(status: 1))])
        certRepMessage = :'PKIXCMP-2009'.encode(:'CertRepMessage', body)
        recipient = CA."PKIHeader"(header, :recipient)
        sender = CA."PKIHeader"(header, :sender)
        senderKID = CA."PKIHeader"(header, :senderKID)
        recipientKID = CA."PKIHeader"(header, :senderKID)
#        protection = CA."PKIHeader"(header, :protection)
        {_,protectionAlg,_} = CA."PKIHeader"(header, :protectionAlg)
        :io.format 'Protection: ~p~n', [code]
        :io.format 'SenderKID: ~p~n', [senderKID]
        :io.format 'RecipientKID: ~p~n', [recipientKID]
        :io.format 'Protection Alg: ~p~n', [CA.ALG.lookup(protectionAlg)]
        pkiheader = CA."PKIHeader"(sender: recipient, recipient: sender, pvno: :cmp2000)
        answer(socket, pkiheader, {:cp,body}, code)
    end

    def answer(socket, header, body, code) do
        message = CA."PKIMessage"(header: header, body: body, protection: code)
        {:ok, bytes} = :'PKIXCMP-2009'.encode(:'PKIMessage', message)
        res =  "HTTP/1.0 200 OK\r\n"
            <> "Server: SYNR CA\r\n"
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
                  {:PKIMessage, header, body, code, _} = dec
                  :io.format 'PKIMessage:~n~p~n', [dec]
                  message(socket, header, body, code)
                  loop(socket)
             {:error, :closed} -> :exit
        end
    end
end