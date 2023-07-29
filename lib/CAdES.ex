defmodule CA.CAdES do

   def readSignature() do
       name = "priv/CAdES/CAdES-X-CA.p7s"
       {:ok, bin} = :file.read_file name
       :io.format '~p~n', [CA.KEP.parseSignData(bin)]
   end

end
