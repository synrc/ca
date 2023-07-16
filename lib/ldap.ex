defmodule CA.LDAP do

   def start(), do: :erlang.spawn(fn -> listen(389) end)
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
   def loop(socket) do
       case :gen_tcp.recv(socket, 0) do
            {:ok, data} ->
                 :io.format '~p~n', [data]
                 case :'LDAP'.decode(:'LDAPMessage',data) do
                      {:ok,decoded} -> :io.format '~p~n', [decoded] ; loop(socket)
                      {:error,_} -> :exit
                 end
            {:error, :closed} -> :exit
       end
   end
end