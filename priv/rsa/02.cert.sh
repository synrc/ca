# generate root cert
openssl req -new -x509 -days 3650 -config synrc.cnf -key certs/caroot.key -out certs/caroot.pem -subj "/C=UA/ST=Kyiv/O=SYNRC/CN=CA"
