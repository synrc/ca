defmodule CA.CRYPTO do

    def e(x,y), do: :erlang.element(x,y)
    def privat(name), do: e(3,:public_key.pem_entry_decode(readPEM("priv/certs/",name)))
    def public(name), do: e(3,e(8, e(2, :public_key.pem_entry_decode(readPEM("priv/certs/",name)))))
    def readPEM(folder, name), do: hd(:public_key.pem_decode(e(2, :file.read_file(folder <> name))))
    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)
    def eccCMS(ukm, len), do: {:'ECC-CMS-SharedInfo', {:'KeyWrapAlgorithm',{2,16,840,1,101,3,4,1,45},:asn1_NOVALUE}, ukm, <<len::32>>}

    def testSMIME() do
        {:ok,base} = :file.read_file "priv/encrypted.txt" ; [_,s] = :string.split base, "\n\n"
        x = :base64.decode(s)
        :file.write_file "priv/encrypted.bin", [x]
        y = :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, x)
        :io.format '~p~n', [y]
        y
    end

    def testCMS() do
        privateKey = privat "maxim.key"
        :io.format '~p~n', [:public_key.pem_entry_decode(readPEM("priv/certs/","maxim.key"))]
        scheme = :secp256r1 # prime256v1
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},data},_}}} = testSMIME()
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,_,[{_,_,encryptedKey}]}}|_] = x
        sharedKey    = shared(publicKey,privateKey,scheme)
        {_,content}  =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', eccCMS(ukm, 256))
        kdf          = KDF.derive(:sha512, sharedKey, 32, content)
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        CA.AES.decrypt(:aes_256_cbc, data, unwrap, :binary.part(iv,2,16))
    end

end