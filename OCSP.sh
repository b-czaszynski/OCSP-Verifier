#!/bin/bash

OPTIND=1

RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
ORANGE='\033[0;33m'
L_CYAN='\033[0;35m'

usage() { printf "Usage: [-s URL] or [-f file with URLs], [-o outputfile]" 1>&2; exit 1; }

if [ $# -le 1 ]; then
	usage
	exit 0;
fi


# Main verification function
OCSP_verify()
{
	printf "\n${L_CYAN}--- Checking:\t$1\n${NC}"
		CERT_PEM="$(timeout 10s openssl s_client -connect $1:443 2>/dev/null < /dev/null | sed -n '/-----BEGIN/,/-----END/p')"

	# Skip if connection could not be established
		case "$?" in
			0)  ;;
			124)
				printf "${RED}[!] Connection to the server failed.${NC}\n"
				echo "$1" >> ./OCSP_RESULTS/inaccessible.txt
				continue ;;
		esac
		OCSP_URI="$(openssl x509 -noout -ocsp_uri -in <(echo "${CERT_PEM}"))"

	# Some certificates might not have the OCSP field, handle error
		if [ -z "$OCSP_URI" ]; then
			printf "${RED}[!]\tEmpty OCSP URL, skipping ${1}...${NC}\n"
			continue
		fi
		printf "\tOCSP URI:\t${OCSP_URI}\n"

	# Retrieve chain of certificates, discarding all additional information
		CERT_CHAIN="$(openssl s_client -connect $1:443 -showcerts 2>/dev/null < /dev/null | sed -n '/-----BEGIN/,/-----END/p')"

	# Count certificates in the chain
		NUM_CERTS=$(grep -w "BEGIN" <(echo "${CERT_CHAIN}") -c)
		printf "Number of certs in chain: \t${NUM_CERTS}\n"

	# If certificate chain is empty, skip
		if [ "$NUM_CERTS" -eq 0 ]; then
			printf "${RED}[!]\tNo certificates received, skipping ${1}...${NC}\n"
			continue
		fi

	# Split chain of certificates into separate files, store in OCSP_RESULTS/temp named "certXX"
		csplit -k -s --elide-empty-files -f ./OCSP_RESULTS/temp/cert <(echo "${CERT_CHAIN}") '/END CERTIFICATE/+1' {$((${NUM_CERTS}-1))}

		CTR=0
		for cert_file in ./OCSP_RESULTS/temp/cert*; do
		# Print certificate if verbose
			if [ $PRINT_CERTS -eq 1 ]; then
				openssl x509 -in $cert_file -text -noout
			fi

		# TODO: Check for CRL
		# Perform an OCSP query
			CERT_CHECK="$(openssl ocsp -issuer "$cert_file" -cert <(echo "${CERT_PEM}") -url ${OCSP_URI} 2> /dev/null)"
			exit_code=$?
			if [ $exit_code -eq 0 ]; then
				printf "\nCert #$CTR\n"
				printf "${BLUE}[i] OCSP request successful.${NC}\n$CERT_CHECK\n"

				# Check what is the OCSP response, look for 'revoked'
				if [[ $CERT_CHECK == *revoked* ]]; then
					printf "${RED}[!] REVOKED CERTIFICATE FOUND!${NC}\n"
					echo "$1" >> ./OCSP_RESULTS/REVOKED_CERTS.txt
				fi

			elif [ $exit_code -ne 0 -a $VERBOSE -eq 1 ]; then
				printf "${ORANGE}[!] OCSP request failed.${NC}\n$CERT_CHECK\n"
				if [[ $CERT_CHECK == *unauthorized* ]]; then
					echo "$1 - unauthorized to query the OCSP server ($OCSP_URI)" >> ./OCSP_RESULTS/inaccessible.txt
				fi
			fi
		CTR=$((CTR+1))
		done

	#TODO: Remove all unnecessary files after it is finished working
	# Remove temprary certificates
		rm -f ./temp/cert*
}


VERBOSE=0
PRINT_CERTS=0
PORT=443

# Input argument processing
while getopts "s:f:vPo:p:" option; do
	case "$option" in
	s) INPUT_STR=$OPTARG
		printf "STR set to $INPUT_STR\n"
		;;
	f) INPUT_FILE=$OPTARG
		printf "FILE set to $INPUT_FILE\n"
		;;
	v) VERBOSE=1
		printf "Verbosity mode on.\n"
		;;
    o) printf "Output redirected to: $OPTARG\n"
		exec > "$OPTARG"
		;;
	P) printf "Cerificate printing: enabled."
		PRINT_CERTS=1
		;;
	p)
	esac
done

# For storing intermediate certificates and query results
mkdir -p ./OCSP_RESULTS/temp

# Process input file line by line
if [ -n "$INPUT_FILE" ]; then
	while read line; do
	#TODO: currently checking only last cert in chain.
		OCSP_verify $line
	done < "$INPUT_FILE"

# Verify OCSP based on single provided URL
elif [ -n "$INPUT_STR" ]; then

	OCSP_verify $INPUT_STR
fi

exit 0;