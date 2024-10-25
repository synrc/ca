defmodule CA.CMC do
    @moduledoc "CA/CMC TLS TCP server."
    require CA

    def code(),  do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
    def start(), do: {:ok, :erlang.spawn(fn -> listen(1839) end)}

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
end