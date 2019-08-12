# generate intermediate key
openssl req -config intermediate/intermediate.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout intermediate/private/int.ca.key.pem -out intermediate/csr/int.ca.csr
