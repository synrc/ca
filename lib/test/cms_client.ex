defmodule CA.CMS.Test do
  @moduledoc false

    def e(x,y), do: :erlang.element(x,y)
    def pem(name), do: hd(:public_key.pem_decode(e(2,:file.read_file(name))))

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
        privateKey = e(3,:public_key.pem_entry_decode(pem("priv/certs/client.key")))
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
