defmodule CA.CMP do

   # IETF 2510:2005 X.509 PKI CMP

   # openssl cmp -cmd genm -server 127.0.0.1:829 \
   #             -recipient "/CN=CMPserver" -ref 1234 -secret pass:0000

   # openssl cmp -cmd ir -server 127.0.0.1:829 \
   #             -path priv/certs -srvcert caroot.pem -ref NewUser \
   #             -secret pass:0000 -certout x.pem -newkey maxim.key.enc -subject "/CN=maxim/O=SYNRC/ST=Kyiv/C=UA"
 
   def start(), do: :erlang.spawn(fn -> listen(829) end)
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
                 {{_,headers},asn} = :asn1rt_nif.decode_ber_tlv(data)
                 [_,body] = :string.split asn, "\r\n\r\n", :all
                 {:ok,dec} = :'PKIXCMP-2009'.decode(:'PKIMessage', body)
                 :io.format 'CMP: ~p~n', [dec]
                 loop(socket)
            {:error, :closed} -> :exit
       end
   end
end