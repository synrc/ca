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
        :crypto.crypto_one_time(:aes_256_cbc,secret,iv,cipher,[{:encrypt,false}]) end

    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)

    def testKDF() do
        {maximK,key} = privat "maxim"
        scheme = :prime256v1
        kdf          = <<246, 12, 141, 164, 154, 173, 117, 144, 14, 3, 156, 213, 42, 25, 211, 160, 130,
                         43, 51, 242, 75, 160, 175, 11, 167, 76, 177, 17, 211, 75, 146, 200>>
        unwrapped    = <<91, 14, 167, 227, 231, 214, 163, 73, 170, 246, 181, 226, 189, 201, 124, 243, 41,
                         106, 120, 60, 134, 166, 142, 197, 183, 120, 127, 214, 23, 232, 212, 134>>
        encryptedKey = <<10, 165, 23, 245, 67, 211, 61, 126, 224, 151, 243, 132, 154, 31, 124, 254, 125,
                         210, 186, 121, 76, 166, 113, 230, 153, 105, 84, 229, 24, 160, 184, 209, 232, 50,
                         153, 61, 186, 20, 194, 95>>
        publicKey    = <<4,15,90,175,28,162,64,100,204,92,124,93,179,53,62,8,61,101,110,91,223,236,93,
                         49,2,190,224,23,19,191,155,26,37,82,99,34,36,80,54,89,204,246,163,0,54,191,
                         57,152,190,11,181,2,108,188,172,182,127,179,162,15,15,192,84,18,10>>
        privateKey   = <<247, 207, 95, 5, 196, 153, 227, 80, 93, 7, 1, 191, 236, 109,
                         205, 218, 155, 121, 203, 134, 243, 66, 116, 49, 205, 157, 50, 65, 245, 9, 105, 49>>
        sharedKey    = shared(publicKey,maximK,scheme)
        unwrap       = :aes_kw.unwrap(encryptedKey, sharedKey)
    end

    def testDecode() do
        data = <<166, 245, 116, 20, 75, 138, 18, 153, 192, 25, 85, 227, 145, 0, 179, 32, 21, 20, 219, 137, 54, 9, 34, 190, 159, 1, 108, 168, 64, 10, 128, 42>>
        iv = <<188, 9, 9, 162, 138, 88, 113, 80, 1, 38, 17, 80, 198, 172, 209, 69>>
        unwrap = <<234, 54, 248, 92, 153, 222, 78, 126, 242, 118, 211, 164, 72, 164, 19, 75,
                   213, 214, 12, 239, 142, 196, 130, 222, 64, 91, 2, 208, 144, 112, 15, 92>>
        decryptCBC(data, unwrap, iv)
    end

    def test() do
        scheme = :prime256v1
        {maximK,key} = privat "maxim"
        {maximP,pub} = public "maxim"
        cms = testCMSX509
        :io.format '~p~n', [cms]
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},msg},_}}} = cms
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,_,[{_,_,encryptedKey}]}}|y] = x
        maximS = shared(publicKey,maximK,scheme)
        :io.format '~p~n', [publicKey]
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
    end

end