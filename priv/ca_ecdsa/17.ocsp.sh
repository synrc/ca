# run OCSP server
openssl ocsp -port 0.0.0.0:8081-text -sha256 -index intermediate/index.txt -CA intermediate/certs/ecdsa_ca_chain.pem -rkey intermediate/private/ocsp_ecdsa_key_rp.pem -rsigner intermediate/certs/ocsp_ecdsa_cert.pem -nrequest 1
