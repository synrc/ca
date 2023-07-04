defmodule CA.CRYPTO do
    @aad "AES256CBC"

    def unwrap() do
        y = "0004290728E36FA052424AB5649D08B62893E1037A96F3A55542A602A3ADC498B6C79962237F3A06B0165B"
            "474E8700F08E5050298E49CE3B2CC55E2FA3752FFCDFEE8A59E76FA2CEFC841A50086D8F47018E5E26BE4D"
            "68B2CD926583A9A41257113C"
        z = "884B58ACC3A022028967505E052BEF8E"
        w = "D434906245409BD25A7EBA7827F42F64"
        x = :oid.unhex "4C5A459B4A305BC8B356571308AEAF7B269BBBE7CB17D09AAC9DCF6868685214D20F40478B0B186B"
    end

    def testCMSX509() do
        {_,bin} = :file.read_file "priv/encrypted.bin"
        :'CryptographicMessageSyntax-2009'.decode(:ContentInfo, bin)
    end

    def privat(name) do
        prefix = "priv/cert/"
        key = :public_key.pem_entry_decode(:erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".key")))))
        {_,_,keyBin,_,_,_} = key
        keyBin
    end

    def public(name) do
        prefix = "priv/cert/"
        pub  = :public_key.pem_entry_decode(:erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".pem")))))
        :erlang.element(3,:erlang.element(8, :erlang.element(2, pub)))
    end

    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)

    def test() do
        scheme = :secp384r1
        aliceK = privat "client"
        aliceP = public "client"
        maximK = privat "server"
        maximP = public "server"
        cms = testCMSX509
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},msg},_}}} = cms
        [{:kari,{_,:v3,{_,{_,_,publicKey}},_,_,[{_,_,encryptedKey}]}}|y] = x
        maximS = shared(aliceP,maximK,scheme)
        aliceS = shared(maximP,aliceK,scheme)
        :io.format('IV: ~tp~n',[iv])
        {cms,[publicKey: publicKey,encryptedKey: encryptedKey, iv: iv, msg: msg]}
    end


end