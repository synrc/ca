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

    def decryptCBC(cipher, secret, iv) do
        :crypto.crypto_one_time(:aes_256_cbc,secret,iv,cipher,[{:encrypt,false}]) end

    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)

    def test____() do
        {maximK,_} = privat "maxim"
        {maximP,_} = public "maxim"
        scheme = :prime256v1
        kdf          = <<72, 107, 155, 26, 72, 48, 84, 17, 196, 223, 216, 171, 80, 69, 237, 114, 43, 195, 185, 109, 228, 129, 171, 72, 73, 223, 122, 52, 129, 156, 101, 121>>
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

    def testKDF() do
#        {maximK,_} = privat "maxim"
#        {maximP,_} = public "maxim"
#        scheme = :prime256v1
#        sharedKey    = shared(publicKey,maximK,scheme)
        sharedKey    = <<0, 23, 75, 69, 228, 151, 69, 27, 32, 251, 44, 195, 58, 217, 225, 184, 169, 242, 86, 179, 98, 202, 182, 149, 194, 58, 0, 63, 18, 87, 112, 173>>
        contentInfo  = <<48, 89, 48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 1, 45, 160, 66, 4, 64, 223, 26, 197, 93, 44, 41, 6, 2, 221, 131, 15, 3, 178, 246, 255, 171, 206, 252, 81, 162, 246, 68, 56, 165, 0, 140, 202, 2, 197, 115, 90, 94, 50, 142, 83, 129, 17, 198, 186, 108, 44, 206, 149, 11, 121, 229, 163, 32, 246, 65, 16, 92, 91, 104, 245, 32, 88, 223, 70, 116, 34, 53, 178, 249, 162, 6, 4, 4, 0, 0, 1, 0>>
        :'CMSECCAlgs-2009-02'.decode(:'ECC-CMS-SharedInfo', contentInfo)
        kdf          = KDF.derive(:sha512, sharedKey, 32, contentInfo)
        encryptedKey = <<48, 209, 23, 117, 214, 149, 195, 133, 187, 142, 81, 82, 162, 44, 102, 31, 148, 163, 53, 98, 159, 61, 20, 221, 173, 49, 230, 242, 113, 246, 19, 51, 197, 41, 225, 28, 83, 139, 169, 97>>
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        data         = <<128, 196, 25, 250, 68, 103, 198, 72, 197, 203, 5, 173, 43, 24, 212, 147, 239, 124, 5, 57, 164, 158, 133, 227, 90, 54, 162, 115, 41, 2, 71, 129>>
        iv           = <<97, 97, 144, 119, 183, 207, 197, 200, 142, 1, 201, 219, 173, 207, 63, 20>>
        decryptCBC(data, unwrap, iv)
    end

    def testUnwrap() do
        kdf          = <<173, 14, 40, 253, 54, 191, 118, 69, 224, 139, 154, 211, 4, 136, 182, 44, 246, 222, 24, 35, 85, 223, 73, 150, 7, 252, 122, 67, 16, 185, 57, 77>>
        encryptedKey = <<93, 239, 14, 185, 169, 133, 226, 122, 96, 26, 16, 228, 196, 154, 190, 213, 60, 65, 223, 176, 166, 109, 37, 253, 107, 17, 1, 206, 16, 130, 160, 79, 8, 107, 241, 218, 187, 7, 132, 89>>
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        data = <<188, 48, 46, 36, 148, 107, 169, 57, 176, 145, 47, 169, 237, 241, 244, 177, 79, 249, 130, 44, 179, 129, 108, 47, 159, 68, 126, 183, 213, 213, 205, 13>>
        iv = <<187, 95, 134, 1, 63, 206, 38, 130, 149, 235, 230, 2, 143, 128, 235, 82>>
        decryptCBC(data, unwrap, iv)
    end

    def testDecode() do
        data   = <<188, 48, 46, 36, 148, 107, 169, 57, 176, 145, 47, 169, 237, 241, 244, 177, 79, 249, 130, 44, 179, 129, 108, 47, 159, 68, 126, 183, 213, 213, 205, 13>>
        iv     = <<187, 95, 134, 1, 63, 206, 38, 130, 149, 235, 230, 2, 143, 128, 235, 82>>
        unwrap = <<7, 54, 202, 106, 82, 159, 14, 38, 154, 188, 199, 36, 41, 123, 161, 56, 142, 171, 46, 246, 62, 18, 243, 1, 140, 31, 48, 224, 138, 166, 53, 36>>
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