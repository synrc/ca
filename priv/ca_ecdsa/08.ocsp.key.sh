# generate OCSP key for signing
openssl req -config intermediate/server.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout intermediate/private/ocsp_ecdsa_key.pem -out intermediate/csr/ocsp_ecdsa.csr -extensions server_cert
