defmodule CA.AES do
    @moduledoc "CA/AES algorithms."

    def keyWrap(x, y), do: :aes_kw.wrap(x, y)
    def keyUnwrap(x, y), do: :aes_kw.unwrap(x, y)

    def e(x,y),       do: :erlang.element(x,y)
    def privat(name), do: e(3,:public_key.pem_entry_decode(readPEM("priv/certs/",name)))
    def public(name), do: e(3,e(8, e(2, :public_key.pem_entry_decode(readPEM("priv/certs/",name)))))
    def readPEM(folder, name),     do: hd(:public_key.pem_decode(e(2, :file.read_file(folder <> name))))
    def shared(pub, key, scheme),  do: :crypto.compute_key(:ecdh, pub, key, scheme)

    def decryptAES128GCM(data, key, _iv) do
        <<iv::binary-16, tag::binary-16, bin::binary>> = data
        :crypto.crypto_one_time_aead(:aes_128_gcm, key, iv, bin, "AES256GCM", tag, false)
    end

    def decryptAES128CCM(data, key, _iv) do
        <<iv::binary-16, tag::binary-16, bin::binary>> = data
        :crypto.crypto_one_time_aead(:aes_128_ccm, key, iv, bin, "AES256GCM", tag, false)
    end

    def decryptAES256GCM(data, key, _iv) do
        <<iv::binary-16, tag::binary-16, bin::binary>> = data
        :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, bin, "AES256GCM", tag, false)
    end

    def decryptAES256CCM(data, key, _iv) do
        <<iv::binary-16, tag::binary-16, bin::binary>> = data
        :crypto.crypto_one_time_aead(:aes_256_ccm, key, iv, bin, "AES256GCM", tag, false)
    end

    def decryptAES256CBC(data, key, iv) do
        :crypto.crypto_one_time(:aes_256_cbc,key,iv,data,[{:encrypt,false},{:padding,:pkcs_padding}])
    end

    def decryptAES128CBC(data, key, iv) do
        :crypto.crypto_one_time(:aes_128_cbc,key,iv,data,[{:encrypt,false},{:padding,:pkcs_padding}])
    end

    def decryptAES256ECB(data, key, _iv) do
        :crypto.crypto_one_time(:aes_256_ecb,key,data,[{:encrypt,false},{:padding,:pkcs_padding}])
    end

    def decryptAES128ECB(data, key, _iv) do
        :crypto.crypto_one_time(:aes_128_ecb,key,data,[{:encrypt,false},{:padding,:pkcs_padding}])
    end

    def encryptAES256ECB(data, key, _iv) do
        :crypto.crypto_one_time(:aes_256_ecb,key,data,[{:encrypt,true},{:padding,:pkcs_padding}])
    end

    def encryptAES128ECB(data, key, _iv) do
        :crypto.crypto_one_time(:aes_128_ecb,key,data,[{:encrypt,true},{:padding,:pkcs_padding}])
    end

    def encryptAES256CBC(data, key, iv) do
        :crypto.crypto_one_time(:aes_256_cbc,key,iv,data,[{:encrypt,true},{:padding,:pkcs_padding}])
    end

    def encryptAES128CBC(data, key, iv) do
        :crypto.crypto_one_time(:aes_128_cbc,key,iv,data,[{:encrypt,true},{:padding,:pkcs_padding}])
    end

    def encryptAES256GCM(data, key, iv) do
        {cipher, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, iv, data, "AES256GCM", true)
        iv <> tag <> cipher
    end

    def encryptAES256CCM(data, key, iv) do
        {cipher, tag} = :crypto.crypto_one_time_aead(:aes_256_ccm, key, iv, data, "AES256GCM", true)
        iv <> tag <> cipher
    end

    def encryptAES128GCM(data, key, iv) do
        {cipher, tag} = :crypto.crypto_one_time_aead(:aes_128_gcm, key, iv, data, "AES256GCM", true)
        iv <> tag <> cipher
    end

    def encryptAES128CCM(data, key, iv) do
        {cipher, tag} = :crypto.crypto_one_time_aead(:aes_128_ccm, key, iv, data, "AES256GCM", true)
        iv <> tag <> cipher
    end

    # public API is ASN.1 based

    def encrypt(:'id-aes256-ECB', data, key, iv), do: encryptAES256ECB(data, key, iv)
    def encrypt(:'id-aes256-CBC', data, key, iv), do: encryptAES256CBC(data, key, iv)
    def encrypt(:'id-aes256-GCM', data, key, iv), do: encryptAES256GCM(data, key, iv)
    def encrypt(:'id-aes256-CCM', data, key, iv), do: encryptAES256CCM(data, key, iv)
    def encrypt(:'id-aes128-ECB', data, key, iv), do: encryptAES128ECB(data, key, iv)
    def encrypt(:'id-aes128-CBC', data, key, iv), do: encryptAES128CBC(data, key, iv)
    def encrypt(:'id-aes128-GCM', data, key, iv), do: encryptAES128GCM(data, key, iv)
    def encrypt(:'id-aes128-CCM', data, key, iv), do: encryptAES128CCM(data, key, iv)

    def decrypt(:'id-aes256-ECB', data, key, iv), do: decryptAES256ECB(data, key, iv)
    def decrypt(:'id-aes256-CBC', data, key, iv), do: decryptAES256CBC(data, key, iv)
    def decrypt(:'id-aes256-GCM', data, key, iv), do: decryptAES256GCM(data, key, iv)
    def decrypt(:'id-aes256-CCM', data, key, iv), do: decryptAES256CCM(data, key, iv)
    def decrypt(:'id-aes128-ECB', data, key, iv), do: decryptAES128ECB(data, key, iv)
    def decrypt(:'id-aes128-CBC', data, key, iv), do: decryptAES128CBC(data, key, iv)
    def decrypt(:'id-aes128-GCM', data, key, iv), do: decryptAES128GCM(data, key, iv)
    def decrypt(:'id-aes128-CCM', data, key, iv), do: decryptAES128CCM(data, key, iv)

    def testSMIME() do
        {:ok,base} = :file.read_file "priv/encrypted.txt" ; [_,s] = :string.split base, "\n\n"
        :'CryptographicMessageSyntax-2010'.decode(:ContentInfo, :base64.decode(s))
    end

    def test() do
      [
        check_SECP384R1_GCM256(),
        check_X25519_GCM256(),
        check_C2PNB368w1_GCM256(),
        check_BrainPoolP512t1_GCM256(),
        check_BrainPoolP512t1_GCM256(),
        check_SECT571_GCM256(),
        check_X448_GCM256(),
        check_X448_GCM128(),
        check_X448_CBC256(),
        check_X448_CBC128(),
        check_X448_ECB128(),
      ]
       :ok
    end

    def check_SECP384R1_GCM256() do # SECP384r1
        scheme = :secp384r1
        aliceP = public "client.pem"
        aliceK = privat "client.key"
        maximP = public "server.pem"
        maximK = privat "server.key"
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_X25519_GCM256() do # X25519
        scheme = :x25519
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_C2PNB368w1_GCM256() do # C2PNB368w1
        scheme = :c2pnb368w1
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_BrainPoolP512t1_GCM256() do # BrainPoolP512t1
        scheme = :brainpoolP512t1
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_SECT571_GCM256() do # SECT571r1
        scheme = :sect571r1
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_X448_GCM256() do # X488
        scheme = :x448
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-GCM', x, aliceS, iv)
        :ok
    end

    def check_X448_GCM128() do # X488
        scheme = :x448
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,16)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,16)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes128-GCM', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes128-GCM', x, aliceS, iv)
        :ok
    end

    def check_X448_CBC256() do # X488
        scheme = :x448
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,32)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,32)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes256-CBC', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes256-CBC', x, aliceS, iv)
        :ok
    end

    def check_X448_CBC128() do # X488
        scheme = :x448
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,16)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,16)
        true = aliceS == maximS
        iv = :crypto.strong_rand_bytes(16)
        x = encrypt(:'id-aes128-CBC', "Success!", maximS, iv)
        "Success!" = decrypt(:'id-aes128-CBC', x, aliceS, iv)
        :ok
    end

    def check_X448_ECB128() do # X488
        scheme = :x448
        {aliceP,aliceK} = :crypto.generate_key(:ecdh, scheme)
        {maximP,maximK} = :crypto.generate_key(:ecdh, scheme)
        maximS = :binary.part(shared(aliceP,maximK,scheme),0,16)
        aliceS = :binary.part(shared(maximP,aliceK,scheme),0,16)
        true = aliceS == maximS
        x = encrypt(:'id-aes128-ECB', "Success!", maximS, "")
        "Success!" = decrypt(:'id-aes128-ECB', x, aliceS, "")
        :ok
    end


end