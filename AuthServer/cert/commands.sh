docker build -t rasha - < Dockerfile

# Generate a random RSA key
openssl genrsa -out privkey-rsa-2048.pkcs1.pem 2048

# Export Public-only RSA Key in PKCS1 (traditional) format
openssl rsa -in privkey-rsa-2048.pkcs1.pem -pubout -out pub-rsa-2048.spki.pem

# Convert PKCS1 (traditional) RSA Keypair to PKCS8 format
openssl pkcs8 -topk8 -nocrypt -in privkey-rsa-2048.pkcs1.pem -out privkey-rsa-2048.pkcs8.pem

# Convert PKCS1 (traditional) RSA Public Key to SPKI/PKIX format
openssl rsa -in pub-rsa-2048.spki.pem -pubin -RSAPublicKey_out -out pub-rsa-2048.pkcs1.pem

docker run --rm -it --init -v ${PWD}:/cert rasha /cert/privkey-rsa-2048.pkcs8.pem > privkey-rsa-2048.jwk.json

docker run --rm -it --init -v ${PWD}:/cert rasha /cert/pub-rsa-2048.spki.pem > pub-rsa-2048.jwk.json
