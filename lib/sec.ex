defmodule CA.CRYPTO do

    def testCMSX509() do
        {_,base} = :file.read_file "priv/encrypted.txt"
        bin = :base64.decode base
        :'CryptographicMessageSyntax-2009'.decode(:ContentInfo, bin)
    end


end