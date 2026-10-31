#!/bin/sh
echo "$CERT_B64" | base64 -d > cert.pem
