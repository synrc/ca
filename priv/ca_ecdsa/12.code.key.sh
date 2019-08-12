# generate code signing key
openssl req -config intermediate/server.cnf -new -newkey ec:<(openssl ecparam -name secp384r1) -keyout intermediate/private/code_signing_key.pem -out intermediate/csr/code_signing.csr -extensions codesign_req
