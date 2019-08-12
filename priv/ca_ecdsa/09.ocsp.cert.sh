# generate OCSP cert for signing
openssl ca -config intermediate/intermediate.cnf -extensions ocsp -days 720 -notext -md sha384 -in intermediate/csr/ocsp_ecdsa.csr -out intermediate/certs/ocsp_ecdsa_cert.pem

# remove the encryption from key
# openssl ec -in intermediate/private/server_ecdsa_key.pem -out intermediate/private/ocsp_ecdsa_key_rp.pem
