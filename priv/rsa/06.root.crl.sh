# generate CRL files
openssl ca -config synrc.cnf -gencrl -out crl/rsaroot.crl
