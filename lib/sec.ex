defmodule CA.CRYPTO do

    def e(x,y), do: :erlang.element(x,y)
    def privat(name), do: e(3,:public_key.pem_entry_decode(readPEM("priv/certs/",name)))
    def public(name), do: e(3,e(8, e(2, :public_key.pem_entry_decode(readPEM("priv/certs/",name)))))
    def readPEM(folder, name), do: hd(:public_key.pem_decode(e(2, :file.read_file(folder <> name))))
    def decryptCBC(cipher, secret, iv), do: :crypto.crypto_one_time(:aes_256_cbc,secret,iv,cipher,[{:encrypt,false}])
    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)
    def eccCMS(ukm, len), do: {:'ECC-CMS-SharedInfo', {:'KeyWrapAlgorithm',{2,16,840,1,101,3,4,1,45},:asn1_NOVALUE}, ukm, <<len::32>>}

    def testSMIME() do
        {:ok,base} = :file.read_file "priv/encrypted.txt" ; [_,s] = :string.split base, "\n\n"
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, :base64.decode(s))
    end

    def testCMS() do
        privateKey = privat "maxim.key"
        scheme = :prime256v1
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},data},_}}} = testSMIME()
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,_,[{_,_,encryptedKey}]}}|_] = x
        sharedKey    = shared(publicKey,privateKey,scheme)
        {_,content}  =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', eccCMS(ukm, 256))
        kdf          = KDF.derive(:sha512, sharedKey, 32, content)
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        decryptCBC(data, unwrap, :binary.part(iv,2,16))
    end

    def testKDF() do
        ukm          = <<223,26,197,93,44,41,6,2,221,131,15,3,178,246,255,171,206,252,81,162,
          246,68,56,165,0,140,202,2,197,115,90,94,50,142,83,129,17,198,186,108,
          44,206,149,11,121,229,163,32,246,65,16,92,91,104,245,32,88,223,70,
          116,34,53,178,249>>
        sharedKey    = <<0, 23, 75, 69, 228, 151, 69, 27, 32, 251, 44, 195, 58, 217, 225, 184, 169, 242, 86, 179, 98, 202, 182, 149, 194, 58, 0, 63, 18, 87, 112, 173>>
        {_,content}  =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', eccCMS(ukm, 256))
        kdf          = KDF.derive(:sha512, sharedKey, 32, content)
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

end