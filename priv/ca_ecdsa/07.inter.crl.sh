# generate intermediate CRL files
openssl ca -config intermediate/intermediate.cnf -gencrl -out intermediate/crl/ecdsaint.crl
