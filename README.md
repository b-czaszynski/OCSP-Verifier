# OCSP-Verifier
Bash script for verifying server's certificate status, based on OCSP responder field.

The script connects to a target URL and retrieves certificate chain the server presents. It then splits the chain into separate certificates and proceeds to retrieve OCSP responder URLs, if certificate contains such information. It then proceeds to contact each OCSP responder to ask for the certificate revocation status. 

If a connection to a URL cannot be established, the script will create a file with all failed URLs. Certificates from each chain are temporarily stored on disc.

## Requirements:
  - openssl
  - coreutils

## Usage:
    -s  :   URL to a web server
    -f  :   path to a file with a list of domains to check
    -o  :   path to a file output shall be stored in
    -v  :   verbose mode
