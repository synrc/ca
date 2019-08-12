# create CA chain file
cat intermediate/certs/int.ca.crt.pem certs/ca.root.crt.pem > intermediate/certs/ecdsa_ca_chain.pem
