defmodule CA.CRYPTO do

    def e(x,y), do: :erlang.element(x,y)
    def privat(name), do: e(3,:public_key.pem_entry_decode(readPEM("priv/certs/",name)))
    def public(name), do: e(3,e(8, e(2, :public_key.pem_entry_decode(readPEM("priv/certs/",name)))))
    def readPEM(folder, name), do: hd(:public_key.pem_decode(e(2, :file.read_file(folder <> name))))
    def shared(pub, key, scheme), do: :crypto.compute_key(:ecdh, pub, key, scheme)
    def eccCMS(ukm, len), do: {:'ECC-CMS-SharedInfo', {:'KeyWrapAlgorithm',{2,16,840,1,101,3,4,1,45},:asn1_NOVALUE}, ukm, <<len::32>>}

    def decryptCMS(cms, privateKey) do
        {:'ECPrivateKey',_,privateKeyBin,{:namedCurve,schemeOID},_,_} = privateKey
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,y,_}}} = cms
        {:EncryptedContentInfo,_,{_,encOID,{_,iv}},data} = y
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,{_,kdfOID,_},[{_,_,encryptedKey}]}}|_] = x
        {scheme,_}  = CA.ALG.lookup(schemeOID)
        {kdf,_}     = CA.ALG.lookup(kdfOID)
        {enc,_}     = CA.ALG.lookup(encOID)
        sharedKey   = shared(publicKey,privateKeyBin,scheme)
        {_,payload} =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', eccCMS(ukm, 256))
        derivedKDF  = case kdf do
           :'dhSinglePass-stdDH-sha512kdf-scheme' -> KDF.derive(:sha512, sharedKey, 32, payload)
           :'dhSinglePass-stdDH-sha384kdf-scheme' -> KDF.derive(:sha384, sharedKey, 32, payload)
           :'dhSinglePass-stdDH-sha256kdf-scheme' -> KDF.derive(:sha256, sharedKey, 32, payload)
        end
        unwrap = :aes_kw.unwrap(encryptedKey, derivedKDF)
        case enc do
           :'id-aes256-CBC' -> CA.AES.decrypt(:aes_256_cbc, data, unwrap, :binary.part(iv,2,16))
           :'id-aes256-GCM' -> CA.AES.decrypt(:aes_256_gcm, data, unwrap, :binary.part(iv,2,16))
           :'id-aes256-ECB' -> CA.AES.decrypt(:aes_256_ecb, data, unwrap, :binary.part(iv,2,16))
        end
    end

    def testDecryptCMS() do
        cms = testSMIME()
        {privateKey,_} = testPrivateKey()
        decryptCMS(cms, privateKey)
    end

    def testSMIME() do
        {:ok,base} = :file.read_file "priv/encrypted.txt" ; [_,s] = :string.split base, "\n\n"
        x = :base64.decode(s)
        :file.write_file "priv/encrypted.bin", [x]
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, x)
    end

    def testPrivateKey() do
        privateKey = :public_key.pem_entry_decode(readPEM("priv/certs/","maxim.key"))
        privateKeyBin = e(3, privateKey)
        {privateKey,privateKeyBin}
    end

    def testCMS() do
        {_,privateKey} = testPrivateKey()
        scheme = :secp256r1 # prime256v1
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{:EncryptedContentInfo,_,{_,_,{_,iv}},data},_}}} = testSMIME()
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,{_,_,_},[{_,_,encryptedKey}]}}|_] = x
        sharedKey    = shared(publicKey,privateKey,scheme)
        {_,content}  =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', eccCMS(ukm, 256))
        kdf          = KDF.derive(:sha512, sharedKey, 32, content)
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        CA.AES.decrypt(:aes_256_cbc, data, unwrap, :binary.part(iv,2,16))
    end

end