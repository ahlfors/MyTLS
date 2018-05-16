# MyTLS
This project is based on my studies of the book "Implementing SSL / TLS Using Cryptography and PKI".

All the algorithms were developed from scratch, even the big number API used to implement RSA:
- Symmetric Criptography: DES, AES, 3DES
- Assymetric Criptography: RSA
- Big Number API for use in RSA
- Signature/MAC Algorithms: MD5, SHA-1, SHA-256/HMAC
- ASN.1/X509 Parser for parse PKI Certificates

There is only the TLS Client available and this client is yet not working properly. 
I am having problem to do TLS Handshake finalize.
In the future I will implement TLS Server, too.


