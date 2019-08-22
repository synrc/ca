openssl s_client -connect localhost:8883 -CAfile certs/caroot.pem -cert certs/client.pem -key certs/client.key -showcerts
