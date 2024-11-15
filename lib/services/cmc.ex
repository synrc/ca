defmodule CA.CMC do
  @moduledoc "CA/CMC TLS TCP server."
  require CA

  # Authority PKI X.509 CMC over TCP RFC 5272 5273 5274 5275 6402

  # [1] https://www.rfc-editor.org/rfc/rfc6402
  # [2] https://www.rfc-editor.org/rfc/rfc5272
  # [3] https://www.rfc-editor.org/rfc/rfc5273
  # [4] https://www.rfc-editor.org/rfc/rfc5274
  # [5] https://www.rfc-editor.org/rfc/rfc5275

  def start_link(port: port), do: {:ok, :erlang.spawn_link(fn -> listen(port) end)}
  def child_spec(opt) do
      %{
        id: CMC,
        start: {CA.CMC, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent,
        shutdown: 500
      }
  end

  def listen(port) do
      :logger.info 'Running CA.CMC with Authority 5.11.15 at 0.0.0.0:~p (tcp)', [port]
      {:ok, socket} = :gen_tcp.listen(port,
        [:binary, {:packet, 0}, {:active, false}, {:reuseaddr, true}])
      accept(socket)
  end

  def accept(socket) do
      {:ok, fd} = :gen_tcp.accept(socket)
      :erlang.spawn(fn -> __MODULE__.loop(fd) end)
      accept(socket)
  end

  def message(_socket, cms) do
      :logger.info 'Unknown message request ~p', [cms]
  end

  def answer(socket, res) do
      :gen_tcp.send(socket, res)
  end

  def loop(socket) do
      case :gen_tcp.recv(socket, 0) do
           {:ok, data} ->
                {:ok, dec} = :'EnrollmentMessageSyntax-2009'.decode(:'PKIData', data)
                {:PKIData, _controlSequence, _reqSequence, cmsSequence, _otherMsgSequence} = dec
                :io.format 'PKIData:~n~p~n', [dec]
                __MODULE__.message(socket, cmsSequence)
                loop(socket)
           {:error, :closed} -> :exit
      end
  end

  def oid(:"id-cmc-identification"),        do: {1,3,6,1,5,5,7,7,2}
  def oid(:"id-cmc-identityProof"),         do: {1,3,6,1,5,5,7,7,3}
  def oid(:"id-cmc-dataReturn"),            do: {1,3,6,1,5,5,7,7,4}
  def oid(:"id-cmc-transactionId"),         do: {1,3,6,1,5,5,7,7,5}
  def oid(:"id-cmc-senderNonce"),           do: {1,3,6,1,5,5,7,7,6}
  def oid(:"id-cmc-recipientNonce"),        do: {1,3,6,1,5,5,7,7,7}
  def oid(:"id-cmc-statusInfo"),            do: {1,3,6,1,5,5,7,7,1}
  def oid(:"id-cmc-addExtensions"),         do: {1,3,6,1,5,5,7,7,8}
  def oid(:"id-cmc-encryptedPOP"),          do: {1,3,6,1,5,5,7,7,9}
  def oid(:"id-cmc-decryptedPOP"),          do: {1,3,6,1,5,5,7,7,10}
  def oid(:"id-cmc-lraPOPWitness"),         do: {1,3,6,1,5,5,7,7,11}
  def oid(:"id-cmc-getCert"),               do: {1,3,6,1,5,5,7,7,15}
  def oid(:"id-cmc-getCRL"),                do: {1,3,6,1,5,5,7,7,16}
  def oid(:"id-cmc-revokeRequest"),         do: {1,3,6,1,5,5,7,7,17}
  def oid(:"id-cmc-regInfo"),               do: {1,3,6,1,5,5,7,7,18}
  def oid(:"id-cmc-responseInfo"),          do: {1,3,6,1,5,5,7,7,19}
  def oid(:"id-cmc-queryPending"),          do: {1,3,6,1,5,5,7,7,21}
  def oid(:"id-cmc-popLinkRandom"),         do: {1,3,6,1,5,5,7,7,22}
  def oid(:"id-cmc-popLinkWitness"),        do: {1,3,6,1,5,5,7,7,23}
  def oid(:"id-cmc-confirmCertAcceptance"), do: {1,3,6,1,5,5,7,7,24}
  def oid(:"id-cmc-statusInfoV2"),          do: {1,3,6,1,5,5,7,7,25}
  def oid(:"id-cmc-trustedAnchors"),        do: {1,3,6,1,5,5,7,7,26}
  def oid(:"id-cmc-authData"),              do: {1,3,6,1,5,5,7,7,27}
  def oid(:"id-cmc-batchRequests"),         do: {1,3,6,1,5,5,7,7,28}
  def oid(:"id-cmc-batchResponses"),        do: {1,3,6,1,5,5,7,7,29}
  def oid(:"id-cmc-publishCert"),           do: {1,3,6,1,5,5,7,7,30}
  def oid(:"id-cmc-modCertTemplate"),       do: {1,3,6,1,5,5,7,7,31}
  def oid(:"id-cmc-controlProcessed"),      do: {1,3,6,1,5,5,7,7,32}
  def oid(:"id-cmc-identityProofV2"),       do: {1,3,6,1,5,5,7,7,33}
  def oid(:"id-cmc-popLinkWitnessV2"),      do: {1,3,6,1,5,5,7,7,34}

  def code(),  do: :binary.encode_hex(:crypto.strong_rand_bytes(8))

end
