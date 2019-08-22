# generate client key
openssl req -config synrc.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout certs/client.key -out certs/client.csr -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=Maxim"
