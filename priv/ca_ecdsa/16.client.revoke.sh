# revoke client cert
openssl ca -config intermediate/intermediate.cnf -revoke intermediate/certs/client_ecdsa_cert.pem
