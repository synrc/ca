# generate root cert
openssl req -config synrc.cnf -days 3650 -new -x509 -key certs/caroot.key -out certs/caroot.pem -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=CA"
