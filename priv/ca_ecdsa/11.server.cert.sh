# generate server cert
#openssl ca -config intermediate/server.cnf -extensions server_cert -days 730 -in intermediate/csr/server_ecdsa.csr -out intermediate/certs/server_ecdsa_cert.pem

# Remove encryption from private key:
# openssl ec -in intermediate/private/server_ecdsa_key.pem -out intermediate/private/server_ecdsa_key_rp.pem

# Combine Cert/Key, pem:
 cat intermediate/certs/server_ecdsa_cert.pem intermediate/private/server_ecdsa_key_rp.pem > intermediate/private/server_ecdsa.pem

# Combine Cert/Key, pkcs12:
# openssl pkcs12 -export -inkey intermediate/private/server_ecdsa_key.pem -in intermediate/certs/server_ecdsa_cert.pem -out intermediate/private/server_ecdsa.p12

