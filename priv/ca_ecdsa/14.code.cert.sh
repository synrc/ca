# generate code signing cert
openssl ca -config intermediate/server.cnf -extensions codesign_req -days 365 -notext -md sha384 -in intermediate/csr/code_signing.csr -out intermediate/certs/code_signing.pem

# Remove Encryption From Private Key:
# openssl ec -in intermediate/private/code_signing_key.pem -out intermediate/private/code_signing_key_rp.pem

# Combine Cert/Key, PEM:
# cat intermediate/certs/code_signing.pem intermediate/private/code_signing_key_rp.pem > intermediate/private/code_signing_wkey.pem

# Combine Cert/Key, PKCS12:
# openssl pkcs12 -export -inkey intermediate/private/code_signing_key.pem -in intermediate/certs/code_signing.pem -out intermediate/private/code_signing_wkey.p12