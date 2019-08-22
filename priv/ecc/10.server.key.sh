# generate server key
openssl req -config synrc.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout certs/server.key -out certs/server.csr  -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=SERVER"