# generate root cert
openssl req -config synrc.cnf -days 3650 -new -x509 -sha384 -extensions v3_ca -key private/ca.root.key.pem -out certs/ca.root.crt.pem
