defmodule CA.CMS do
    @moduledoc "CA/CMS library."

    def map(:'dhSinglePass-stdDH-sha512kdf-scheme'),   do: {:kdf,  :sha512}
    def map(:'dhSinglePass-stdDH-sha384kdf-scheme'),   do: {:kdf,  :sha384}
    def map(:'dhSinglePass-stdDH-sha256kdf-scheme'),   do: {:kdf,  :sha256}
    def map(:'dhSinglePass-stdDH-hkdf-sha256-scheme'), do: {:hkdf, :sha256}
    def map(:'dhSinglePass-stdDH-hkdf-sha384-scheme'), do: {:hkdf, :sha384}
    def map(:'dhSinglePass-stdDH-hkdf-sha512-scheme'), do: {:hkdf, :sha512}

    def sharedInfo(ukm, len), do: {:'ECC-CMS-SharedInfo',
        {:'KeyWrapAlgorithm',{2,16,840,1,101,3,4,1,45},:asn1_NOVALUE}, ukm, <<len::32>>}

    # CMS Codec KARI: ECC+KDF/ECB+AES/KW+256/CBC

    def kari(kari, privateKeyBin, schemeOID, encOID, data, iv) do
        {:'KeyAgreeRecipientInfo',:v3,{_,{_,_,publicKey}},ukm,{_,kdfOID,_},[{_,_,encryptedKey}]} = kari
        {scheme,_}  = CA.ALG.lookup(schemeOID)
        {kdf,_}     = CA.ALG.lookup(kdfOID)
        {enc,_}     = CA.ALG.lookup(encOID)
        sharedKey   = :crypto.compute_key(:ecdh,publicKey,privateKeyBin,scheme)
        {_,payload} = :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', sharedInfo(ukm,256))
        derived     = case map(kdf) do
            {:kdf,hash} -> CA.KDF.derive({:kdf,hash},  sharedKey, 32, payload)
           {:hkdf,hash} -> CA.HKDF.derive({:kdf,hash}, sharedKey, 32, payload)
        end
        unwrap      = CA.AES.keyUnwrap(encryptedKey, derived)
        res         = CA.AES.decrypt(enc, data, unwrap, iv)
        {:ok, res}
    end

    # CMS Codec KTRI: RSA+RSAES-OAEP

    def ktri(ktri, privateKeyBin, encOID, data, iv) do
        {:'KeyTransRecipientInfo',_vsn,_,{_,schemeOID,_},key} = ktri
        {:rsaEncryption,_} = CA.ALG.lookup schemeOID
        {enc,_} = CA.ALG.lookup(encOID)
        sessionKey = :public_key.decrypt_private(key, privateKeyBin)
        res = CA.AES.decrypt(enc, data, sessionKey, iv)
        {:ok, res}
    end

    # CMS Codec KEKRI: KEK+AES-KW+CBC

    def kekri(kekri, privateKeyBin, encOID, data, iv) do
        {:'KEKRecipientInfo',_vsn,_,{_,kea,_},encryptedKey} = kekri
        _ = CA.ALG.lookup(kea)
        {enc,_} = CA.ALG.lookup(encOID)
        unwrap = CA.AES.keyUnwrap(encryptedKey,privateKeyBin)
        res = CA.AES.decrypt(enc, data, unwrap, iv)
        {:ok, res}
    end

    # CMS DECRYPT API

    def decrypt(cms, {schemeOID, privateKeyBin}) do
        {:ok,{:ContentInfo,_,{:EnvelopedData,_,_,x,y,_}}} = cms
        {:EncryptedContentInfo,_,{_,encOID,{_,<<_::16,iv::binary>>}},data} = y
                case :proplists.get_value(:kari,  x, []) do
          [] -> case :proplists.get_value(:ktri,  x, []) do
          [] -> case :proplists.get_value(:kekri, x, []) do
          [] -> case :proplists.get_value(:pwri,  x, []) do
          [] -> {:error, "Unknown Other Recepient Info"}
                pwri  -> pwri(pwri,   privateKeyBin, encOID, data, iv) end
                kekri -> kekri(kekri, privateKeyBin, encOID, data, iv) end
                ktri  -> ktri(ktri,   privateKeyBin, encOID, data, iv) end
                kari  -> kari(kari,   privateKeyBin, schemeOID, encOID, data, iv)
        end
    end

    # CMS Codec PWRI: PBKDF2+AES-KW+CBC

    def pwri(pwri, privateKeyBin, encOID, data, iv) do
        {:error, ["PWRI not implemented", pwri, privateKeyBin, encOID, data, iv]}
    end

    # Test

    def pem(name), do: hd(:public_key.pem_decode(:erlang.element(2,:file.read_file(name))))

    def testDecryptECC(), do: CA.CMS.decrypt(testECC(), testPrivateKeyECC())
    def testDecryptKEK(), do: CA.CMS.decrypt(testKEK(), testPrivateKeyKEK())
    def testDecryptRSA(), do: CA.CMS.decrypt(testRSA(), testPrivateKeyRSA())
    def test(),           do:
       [
          testDecryptECC(),
          testDecryptKEK(),
          testDecryptRSA(),
          testCMS(),
       ]

    def testPrivateKeyECC() do
        privateKey = :public_key.pem_entry_decode(pem("priv/certs/client.key"))
        {:'ECPrivateKey',_,privateKeyBin,{:namedCurve,schemeOID},_,_} = privateKey
        {schemeOID,privateKeyBin}
    end

    def testPrivateKeyKEK() do
        {:kek, :binary.decode_hex("0123456789ABCDEF0123456789ABCDEF")}
    end

    def testPrivateKeyRSA() do
        {:ok,bin} = :file.read_file("priv/rsa-cms.key")
        pki = :public_key.pem_decode(bin)
        [{:PrivateKeyInfo,_,_}] = pki
        rsa = :public_key.pem_entry_decode(hd(pki))
        {:'RSAPrivateKey',:'two-prime',_n,_e,_d,_,_,_,_,_,_} = rsa
        {:rsaEncryption,rsa}
    end

    def testECC() do
        {:ok,base} = :file.read_file "priv/certs/encrypted.txt"
        [_,s] = :string.split base, "\n\n"
        x = :base64.decode s
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, x)
    end

    def testKEK() do
        {:ok,base} = :file.read_file "priv/certs/encrypted2.txt"
        [_,s] = :string.split base, "\n\n"
        x = :base64.decode s
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, x)
    end

    def testRSA() do
        {:ok,x} = :file.read_file "priv/rsa-cms.bin"
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, x)
    end

    def testCMS() do
        privateKey = :erlang.element(3,:public_key.pem_entry_decode(pem("priv/certs/client.key")))
        scheme = :secp384r1
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,{_,_,{_,_,{_,<<_::16,iv::binary>>}},data},_}}} = testECC()
        [{:kari,{_,:v3,{_,{_,_,publicKey}},ukm,_,[{_,_,encryptedKey}]}}|_] = x
        sharedKey   = :crypto.compute_key(:ecdh,publicKey,privateKey,scheme)
        {_,content}  =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', CA.CMS.sharedInfo(ukm,256))
        kdf          = CA.KDF.derive({:kdf, :sha256}, sharedKey, 32, content)
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        CA.AES.decrypt(:'id-aes256-CBC', data, unwrap, iv)
    end

end