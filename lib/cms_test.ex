defmodule CA.CMS.Test do

#   S/MIME Working Group: https://datatracker.ietf.org/wg/smime/documents/

#   Implementations MUST support key transport, key agreement, and
#   previously distributed symmetric key-encryption keys, as represented
#   by ktri, kari, and kekri, respectively.

#   Implementations MAY support the password-based key management as represented by pwri.
#   Implementations MAY support any other key management technique
#   such as Boneh-Franklin and Boneh-Boyen Identity-Based Encryption (RFC 5409)
#   or other SYNRC encryption techniques.

#   IETF: 5990, 5911, 5750--5754, 5652, 5408, 5409, 5275, 5126,
#   5035, 4853, 4490, 4262, 4134, 4056, 4010, 3850, 3851, 3852,
#   3854, 3855, 3657, 3560, 3565, 3537, 3394, 3369, 3370, 3274,
#   3114, 3278, 3218, 3211, 3217, 3183, 3185, 3125--3126, 3058,
#   2984, 2876, 2785, 2630, 2631, 2632, 2633, 5083, 5084, 2634.

    # ECC openssl cms support
    # openssl cms -decrypt -in encrypted.txt -inkey client.key -recip client.pem
    # openssl cms -encrypt -aes256 -in message.txt -out encrypted.txt \
    #                      -recip client.pem -keyopt ecdh_kdf_md:sha256

    # RSA GnuPG S/MIME support
    # gpgsm --list-keys
    # gpgsm --list-secret-keys
    # gpgsm -r 0xD3C8F78A -e CNAME > cms.bin
    # gpgsm -u 0xD3C8F78A -d cms.bin
    # gpgsm --export-secret-key-p12 0xD3C8F78A > key.bin
    # openssl pkcs12 -in key.bin -nokeys -out public.pem
    # openssl pkcs12 -in key.bin -nocerts -nodes -out private.pem

    # KEK openssl cms support
    # openssl cms -encrypt -secretkeyid 07 -secretkey 0123456789ABCDEF0123456789ABCDEF \
    #             -aes256 -in message.txt -out encrypted2.txt
    # openssl cms -decrypt -secretkeyid 07 -secretkey 0123456789ABCDEF0123456789ABCDEF \
    #             -in encrypted2.txt

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
        kdf          = KDF.derive(:sha256, sharedKey, 32, content)
        unwrap       = :aes_kw.unwrap(encryptedKey, kdf)
        CA.AES.decrypt(:'id-aes256-CBC', data, unwrap, iv)
    end

end
