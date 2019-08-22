# generate server cert
#openssl req -new -days 365 -key certs/server.key -out certs/server.csr -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=SERVER"
openssl ca -config synrc.cnf -extensions server_cert -days 730 -in certs/server.csr -out certs/server.pem -cert certs/caroot.pem -keyfile certs/caroot.key
