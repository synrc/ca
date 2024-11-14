defmodule CA.OCSP do
  @moduledoc "CA/OCSP TCP server."
  require CA

  def code(),  do: :binary.encode_hex(:crypto.strong_rand_bytes(8))

  def start_link(port: port), do: {:ok, :erlang.spawn_link(fn -> listen(port) end)}
  def child_spec(opt) do
      %{
        id: OCSP,
        start: {CA.OCSP, :start_link, [opt]},
        type: :supervisor,
        restart: :permanent,
        shutdown: 500
      }
  end

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
                  {:ok, dec} = :'OCSP'.decode(:OCSPRequest, data)
                  :io.format 'OCSPRequest:~n~p~n', [dec]
                  __MODULE__.message(socket, dec)
                  loop(socket)
             {:error, :closed} -> :exit
        end
    end
end