defmodule CA.CRYPTO do
    @aad "AES256CBC"

    def testCMSX509() do
        {_,base} = :file.read_file "priv/encrypted.txt"
        bin = :base64.decode base
        :'CryptographicMessageSyntax-2009'.decode(:ContentInfo, bin)
    end

    def privat(name) do
        prefix = "priv/"
        key = :public_key.pem_entry_decode(:erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".key")))))
        {_,_,keyBin,_,_,_} = key
        keyBin
    end

    def public(name) do
        prefix = "priv/"
        pub  = :public_key.pem_entry_decode(:erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".pem")))))
        :erlang.element(3,:erlang.element(8, :erlang.element(2, pub)))
    end

    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)

    def test() do
        key = privat "client"
        public = public "client"
         {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,_,cipher},_}}} = CA.CRYPTO.testCMSX509
        [kari: {_,:v3,{_,{_,_,pub}},_,_,[{_,_,data}]}] = x
        {pub,public,data,key,cipher}

    end


end