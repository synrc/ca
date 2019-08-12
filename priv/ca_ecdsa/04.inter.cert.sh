# generate intermediate cert
openssl ca -config synrc.cnf -extensions v3_intermediate_ca -days 3600 -md sha384 -in intermediate/csr/int.ca.csr -out intermediate/certs/int.ca.crt.pem
