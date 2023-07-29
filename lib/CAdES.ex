defmodule CA.CAdES do
   @moduledoc "CA/CAdES signature/validation."

   def readSignature() do
       name = "priv/CAdES/CAdES-X-CA.p7s"
       {:ok, bin} = :file.read_file name
       :io.format '~p~n', [CA.QDS.parseSignData(bin)]
   end

end
