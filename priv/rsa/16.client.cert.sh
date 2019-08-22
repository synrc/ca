# generate client cert
openssl req -new -days 365 -key certs/client.key -out certs/client.csr -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=Maxim"
openssl ca -config synrc.cnf -extensions usr_cert -days 365 -in certs/client.csr -out certs/client.pem -cert certs/caroot.pem -keyfile certs/caroot.key

# Combine Cert/Key, PKCS12:
#openssl pkcs12 -export -inkey intermediate/private/client_ecdsa_key.pem -in intermediate/certs/client_ecdsa_cert.pem -out intermediate/private/client_ecdsa.p12

