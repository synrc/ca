# generate root key
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out private/ca.root.key.pem
