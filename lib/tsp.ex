defmodule CA.TSP do
    @moduledoc "CA/TSP server."
    require CA

    def code(),  do: :binary.encode_hex(:crypto.strong_rand_bytes(8))
    def start(), do: :erlang.spawn(fn -> listen(1849) end)

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
                  {:ok, dec} = :KEP.decode(:TimeStampReq, data)
                  :io.format 'TimeStampReq:~n~p~n', [dec]
                  __MODULE__.message(socket, dec)
                  loop(socket)
             {:error, :closed} -> :exit
        end
    end
end