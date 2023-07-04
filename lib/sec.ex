defmodule CA.CRYPTO do

    def testCMSX509() do
        {_,bin} = :file.read_file "priv/encrypted.bin"
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, bin)
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

    for fun <- ~w(md5 sha sha224 sha256 sha384 sha512)a do
      len = fun |> :crypto.hash("") |> byte_size()
      defp hash_length(unquote(fun)) do
        unquote(len)
      end
    end

    def kdf(hash_fun, ikm, len, salt \\ "", info \\ ""), do: expand(hash_fun, extract(hash_fun, ikm, salt), len, info)
    def extract(hash_fun, ikm, salt \\ ""), do: :crypto.mac(:hmac, hash_fun, salt, ikm)
    def expand(hash_fun, prk, len, info \\ "") do
        hash_len = hash_length(hash_fun)
        n = Float.ceil(len/hash_len) |> round()
        full = Enum.scan(1..n, "", fn index, prev ->
             data = prev <> info <> <<index>>
            :crypto.mac(:hmac, hash_fun, prk, data)
         end) |> Enum.reduce("", &Kernel.<>(&2, &1))
        <<output :: unit(8)-size(len), _ :: binary>> = full
        <<output :: unit(8)-size(len)>> end

    def decryptCBC(cipher, secret, iv) do
        secret = :binary.part(secret, 0, 16)
        :crypto.crypto_one_time(:aes_256_cbc,secret,iv,cipher,[{:encrypt,false}]) end

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
        encryptedKey2 = :binary.part(encryptedKey, 2, 16)
        maximS = shared(aliceP,maximK,scheme)
        aliceS = shared(maximP,aliceK,scheme)
        aliceS == maximS
        derived = kdf(:sha256, aliceS, :erlang.size(aliceS))
        unwrap = :aes_kw.unwrap(encryptedKey2, derived, iv)
        :io.format('~p~n',
           [{cms,[ publicKey: aliceP,
                   senderPublic: publicKey,
                   encryptedKey: encryptedKey,
                   kdf: derived,
#                   unwrapped: unwrap,
                   encryptedMessage: msg,
                   iv: iv]}])
#        decryptCBC(msg, unwrap, iv)
    end

end