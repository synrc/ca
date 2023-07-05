defmodule CA.CRYPTO do

    def testCMSX509() do
        {_,base} = :file.read_file "priv/encrypted.txt"
        [_,s] = :string.split base, "\n\n" # S/MIME
        bin = :base64.decode s
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, bin)
    end

    def privat(name) do
        prefix = "priv/certs/"
        bin = :erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".key"))))
        key = :public_key.pem_entry_decode(bin)
        {_,_,keyBin,_,_,_} = key
        :io.format '~p~n', [key]
        {keyBin,bin}
    end

    def public(name) do
        prefix = "priv/certs/"
        bin = :erlang.hd(:public_key.pem_decode(:erlang.element(2, :file.read_file(prefix <> name <> ".pem"))))
        pub = :public_key.pem_entry_decode(bin)
        :io.format '~p~n', [pub]
        keyBin = :erlang.element(3,:erlang.element(8, :erlang.element(2, pub)))
        {keyBin,bin}
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
        scheme = :prime256v1
        {maximK,key} = privat "maxim"
        {maximP,pub} = public "maxim"
        cms = testCMSX509
        :io.format '~p~n', [cms]
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},msg},_}}} = cms
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,_,[{_,_,encryptedKey}]}}|y] = x
        encryptedKey2 = :binary.part(encryptedKey, 2, 16)
        maximS = shared(maximP,maximK,scheme)
        derived = kdf(:sha256, maximS, :erlang.size(maximS))
#        unwrap = :aes_kw.unwrap(encryptedKey, derived)
        [ cert: pub,
          priv: key,
          publicKey: maximP,
          privateKey: maximK,
          sharedKey: maximS,
          ukm: ukm,
          senderPublic: publicKey,
          encryptedKey: encryptedKey,
          encryptedMessage: msg,
          iv: iv]
#        decryptCBC(msg, unwrap, iv)
    end

end