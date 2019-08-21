# generate client key
openssl req -config intermediate/server.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout intermediate/private/client_ecdsa_key.pem -out intermediate/csr/client_ecdsa.csr
