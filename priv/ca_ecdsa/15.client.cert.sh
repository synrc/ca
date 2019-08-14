# generate client cert
openssl ca -config intermediate/server.cnf -extensions usr_cert -days 730 -in intermediate/csr/client_ecdsa.csr -out intermediate/certs/client_ecdsa_cert.pem

# Combine Cert/Key, PKCS12:
#openssl pkcs12 -export -inkey intermediate/private/client_ecdsa_key.pem -in intermediate/certs/client_ecdsa_cert.pem -out intermediate/private/client_ecdsa.p12

