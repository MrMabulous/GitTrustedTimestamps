#!/bin/bash
#
#    RFC3161 and RFC5816 Timestamping for git repositories.
#
#    Copyright (c) 2021 Mabulous GmbH
#    Authors: Matthias Bühlmann
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#    
#    The interactive user interfaces in modified source and object code versions
#    of this program must display Appropriate Legal Notices, as required under
#    Section 5 of the GNU Affero General Public License version 3. In accordance
#    with Section 7(b) of the GNU Affero General Public License, you must retain
#    the Info line in every timestamp that is created or manipulated using a
#    covered work.
#    
#    You can be released from the requirements of the license by purchasing
#    a commercial license. Buying such a license is mandatory as soon as you
#    develop commercial activities involving this software without
#    disclosing the source code of your own applications.
#    These activities include: offering paid services to customers as an ASP,
#    providing data storage and archival services, shipping this software with a 
#    closed source product.
#    
#    For more information, please contact Mabulous GmbH at this
#    address: info@mabulous.com
#

DIR="${BASH_SOURCE%/*}"
if [[ ! -d "$DIR" ]]; then DIR="$PWD"; fi
. "$DIR/timestamping"

TSA_URL="$1"

print_usage() {
  echo "  helper script to add the root certificate of a TSA to the trustanchors"
  echo "  usage:   ./trust.sh <tsa_url>"
  echo "  example: ./trust.sh https://freetsa.org/tsr"
  echo "    This will add the root certificate for freetsa.org to the trusted"
  echo "    root certificates. This trust is local to this repository"
}

if [ -z "$TSA_URL" ]; then
  print_usage
  exit 1
fi

DUMMY_DIGEST=$(echo "0" | git hash-object --stdin)
DUMMY_TOKEN="$TMP_DIR"/token.tst

request_token "$TSA_URL" "$DUMMY_DIGEST" false "$DUMMY_TOKEN"

CERTIFICATES="$TMP_DIR"/certificates.pem
build_certificate_chain_for_token "$DUMMY_TOKEN" "$DUMMY_DIGEST" "$TSA_URL" "$CERTIFICATES"

#extract all individual certificates from CERTIFICATES
NUM_CERTS=$(cat "$CERTIFICATES" \
            | awk '/-----BEGIN CERTIFICATE-----/ { i++; } /-----BEGIN CERTIFICATE-----/, /-----END CERTIFICATE-----/ \
            { print > tmpdir i ".extracted.pem.cer" } END {print i}' tmpdir="$TMP_DIR/")

ROOT_CERT="$TMP_DIR"/"$NUM_CERTS".extracted.pem.cer

echo "Verifying that $ROOT_CERT is self signed"
if ! openssl verify -CAfile "$ROOT_CERT" "$ROOT_CERT" &> "$OUT_STREAM"; then
  echo_error "Error: could not find root certificate for $TSA_URL"
  exit 1
fi

HASH=$(openssl x509 -inform PEM -in "$ROOT_CERT" -noout -subject_hash)
TARGET_FILE="$CA_PATH"/"$HASH".0

echo_warning "This will add the following certificate to $CA_PATH and it will subsequently be trusted for timestamp tokens."
openssl x509 -inform PEM -in "$ROOT_CERT" -noout -text

read -r -p "Are you sure? [y/N] " RESPONSE
if [[ "$RESPONSE" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo -n > "$TARGET_FILE"
  openssl x509 -in "$ROOT_CERT" -noout -subject >> "$TARGET_FILE"
  echo '' >> "$TARGET_FILE"
  openssl x509 -in "$ROOT_CERT" -noout -issuer >> "$TARGET_FILE"
  echo '' >> "$TARGET_FILE"
  cat "$ROOT_CERT" >> "$TARGET_FILE"
  echo '' >> "$TARGET_FILE"
  echo_warning "Added cetificate as $TARGET_FILE"
else
    echo_warning "Aborted."
fi
exit 0
