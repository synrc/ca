# remove the encryption from key
openssl ec -in intermediate/private/server_ecdsa_key.pem -out intermediate/private/ocsp_ecdsa_key_rp.pem
