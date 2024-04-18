#!/bin/bash


# Read certificate chain contents
openssl x509 -in certchain.pem -text

# Generate new self-signed certificate
openssl req -new -x509 -days 365 -nodes -out certchain.pem -keyout private.pem
