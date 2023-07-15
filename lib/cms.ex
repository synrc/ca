defmodule CA.CMS do

    def map(:'dhSinglePass-stdDH-sha512kdf-scheme'), do: :sha512
    def map(:'dhSinglePass-stdDH-sha384kdf-scheme'), do: :sha384
    def map(:'dhSinglePass-stdDH-sha256kdf-scheme'), do: :sha256

    def sharedInfo(ukm, len), do: {:'ECC-CMS-SharedInfo',
        {:'KeyWrapAlgorithm',{2,16,840,1,101,3,4,1,45},:asn1_NOVALUE}, ukm, <<len::32>>}

    # CMS Codec KARI: ECC+KDF/ECB+AES/KW+256/CBC

    def kari(kari, privateKeyBin, schemeOID, encOID, data, iv) do
        {:'KeyAgreeRecipientInfo',:v3,{_,{_,_,publicKey}},ukm,{_,kdfOID,_},[{_,_,encryptedKey}]} = kari
        {scheme,_}  = CA.ALG.lookup(schemeOID)
        {kdf,_}     = CA.ALG.lookup(kdfOID)
        {enc,_}     = CA.ALG.lookup(encOID)
        sharedKey   = :crypto.compute_key(:ecdh,publicKey,privateKeyBin,scheme)
        {_,payload} =  :'CMSECCAlgs-2009-02'.encode(:'ECC-CMS-SharedInfo', sharedInfo(ukm,256))
        derived = KDF.derive(map(kdf), sharedKey, 32, payload)
        unwrap = CA.AES.KW.unwrap(encryptedKey, derived)
        res = CA.AES.decrypt(enc, data, unwrap, iv)
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
        unwrap = CA.AES.KW.unwrap(encryptedKey,privateKeyBin)
        res = CA.AES.decrypt(enc, data, unwrap, iv)
        {:ok, res}
    end

    # CMS DECRYPT API

    def decrypt(cms, {schemeOID, privateKeyBin}) do
        {_,{:ContentInfo,_,{:EnvelopedData,_,_,x,y,_}}} = cms
        {:EncryptedContentInfo,_,{_,encOID,{_,<<_::16,iv::binary>>}},data} = y
        case :proplists.get_value(:kari, x, []) do
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
        {:error, ["PWRI not implemented",pwri, privateKeyBin, encOID, data, iv]}
    end

end