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

# If commit contains timestamp tokens, validates them.
# param1: commit hash
# returns: 0 if the commit contains no timestamp tokens or contains at least one
# valid timestamp token. If there are invalid timestamp tokens and no valid
# timestamp token, returns 1. If there are both valid and invalid timestamp
# tokens, the function will return 0 but echo a warning about the invalid token.
validate_commit() {
  local COMMIT_HASH="$1"
  log "validate_commit for $COMMIT_HASH"
  
  local COMMIT_CONTENT=$(git cat-file -p "$COMMIT_HASH")
  if [ -z "$COMMIT_CONTENT" ]; then
    echo_error "Invalid commit hash $COMMIT_HASH"
    return 1
  fi
  #remove files from possible previous runs
  rm -f "$TMP_DIR"/*.extracted_token.pem
  rm -f "$TMP_DIR"/*.extracted_token.url
  #extract timestamp tokens
  local URL_START=${#TRAILER_TOKEN}
  URL_START=$(( $URL_START + 2))
  local NUM_EXTRACTED=$(echo -n "$COMMIT_CONTENT" | awk '$0~trailertoken{ i++; print substr($0,"$URL_START") > tmpdir i ".extracted_token.url" } /-----END/{show=0} show{print substr($0,2) > tmpdir i ".extracted_token.pem"} /-----BEGIN/{show=1} END {print i}' tmpdir="$TMP_DIR/" trailertoken="$TRAILER_TOKEN")
  if [ -z "$NUM_EXTRACTED" ]; then
    NUM_EXTRACTED=0
  fi
  #iterate over extracted base64 encodings, convert to DER, if it is a timestamp token, evaluate it.
  local ERROR_INFO_FILE="$TMP_DIR"/error_info.txt
  local ERROR_INFO=""
  local TMP_DER="$TMP_DIR"/extracted_token.der
  local TMP_TOKEN="$TMP_DIR"/extracted_token.tst
  local NUM_VALID=0
  local NUM_INVALID=0
  local NUM_SKIPPED=0
  local PARENT_HASH=$(git cat-file -p "$COMMIT_HASH" | awk '/^$/{exit} /parent/ {print}' | sed 's/parent //')
  while ls "$TMP_DIR"/*.extracted_token.pem &> "$OUT_STREAM" && read EXTRACTED_TOKEN_PEM; do
    openssl base64 -d -in "$EXTRACTED_TOKEN_PEM" -out "$TMP_DER"
    #since a commit might contain some unrelated trailer with the name "Timestamp:" that also contains PEM header and footer, non-timestamp-tokens should be skipped
    if ! openssl ts -reply -token_in -token_out -in "$TMP_DER" -out "$TMP_TOKEN" &> "$OUT_STREAM"; then
      echo_warning "A PEM encoded trailer labeled $TRAILER_TOKEN has been found in commit $COMMIT_HASH which does not seem to be a timestamp token. Skipping."
      ((NUM_SKIPPED++))
      continue
    else
      #this is a token, validate it!
      local DIGEST=''
      get_token_digest "$TMP_TOKEN" DIGEST
      if [ "${DIGEST,,}" != "${PARENT_HASH,,}" ]; then
        echo_warning "Token from $TSA_URL in commit $COMMIT_HASH is invalid because the contained digest $DIGEST does not match the timestamped hash $PARENT_HASH"
        ((NUM_INVALID++))
        continue
      fi
      local SIGNING_CERT_ID=''
      get_tsa_cert_id "$TMP_TOKEN" SIGNING_CERT_ID
      local TOKEN_UNIXTIME=''
      get_token_unix_time "$TMP_TOKEN" TOKEN_UNIXTIME
      local TSA_URL_FILE="${EXTRACTED_TOKEN_PEM/.pem/.url}"
      local TSA_URL=$(cat "$TSA_URL_FILE")
      local CERT_CHAIN_FILE="$LTV_DIR"/certs/"$SIGNING_CERT_ID".cer
      if [ ! -f "$CERT_CHAIN_FILE" ]; then
        #If LTV data is not in the working directory, try to check it out from the corresponding commit
        local TMP_CERT_CHAIN_FILE="$TMP_DIR"/"$SIGNING_CERT_ID".cer
        local PATH_SPEC=$(realpath --relative-to="$ROOT_DIR" "$CERT_CHAIN_FILE")
        local CERT_CHAIN_CONTENT=$(git show "$COMMIT_HASH":"$PATH_SPEC") && echo -n "$CERT_CHAIN_CONTENT" > "$TMP_CERT_CHAIN_FILE"
        CERT_CHAIN_FILE="$TMP_CERT_CHAIN_FILE"
      fi
      if [ ! -f "$CERT_CHAIN_FILE" ]; then
        #if ltv data has not been stored for this commit, try to contact TSA to recreate it
        if ! build_certificate_chain_for_token "$TMP_TOKEN" "$DIGEST" "$TSA_URL" "$CERT_CHAIN_FILE"; then
          echo_warning "Token from $TSA_URL in commit $COMMIT_HASH could not be validated since neither LTV data of certificate chain could be found nor could the certificate chain be recreated from the TSA url."
          ((NUM_INVALID++))
          continue
        fi
      fi
      #$CERT_CHAIN_FILE at this point contains certificate chain of token's signing certificate.
      #first validate the token itself at the time of timestamping
      if ! openssl ts -verify -digest "$DIGEST" -in "$TMP_TOKEN" -token_in -attime "$TOKEN_UNIXTIME" \
                  -CApath "$CA_PATH" -untrusted "$CERT_CHAIN_FILE" 1> "$OUT_STREAM" 2> "$ERROR_INFO_FILE"; then
          ERROR_INFO=$(cat "$ERROR_INFO_FILE")
          echo_warning "Token from $TSA_URL in commit $COMMIT_HASH could not be validated since it is invalid or its rootCA isn't trusted: $ERROR_INFO"
          ((NUM_INVALID++))
          continue
      fi

      #now validate the issuing certificate at the time of timestamping, using historical CRLs
      local CRL_CHAIN_FILE="$LTV_DIR"/crls/"$SIGNING_CERT_ID".crl
      local HISTORIC_CRL_CHAIN_FILE="$TMP_DIR"/"$SIGNING_CERT_ID".crl
      local PATH_SPEC=$(realpath --relative-to="$ROOT_DIR" "$CRL_CHAIN_FILE")
      local CRL_CHAIN_CONTENT=$(git show "$COMMIT_HASH":"$PATH_SPEC") && echo "$CRL_CHAIN_CONTENT" > "$HISTORIC_CRL_CHAIN_FILE"
      if [ ! -f "$HISTORIC_CRL_CHAIN_FILE" ]; then
        echo_warning "Token from $TSA_URL in commit $COMMIT_HASH could not be validated since no CRL data valid at the time of timestamping could be found."
        ((NUM_INVALID++))
        continue
      fi
      #historic CRL data available, check if the signing certificate was valid at the time of timestamping
      if ! openssl verify -attime "$TOKEN_UNIXTIME" -CApath "$CA_PATH" -CRLfile "$HISTORIC_CRL_CHAIN_FILE" \
                          -crl_check_all -untrusted "$CERT_CHAIN_FILE" "$CERT_CHAIN_FILE" 1> "$OUT_STREAM" 2> "$ERROR_INFO_FILE"; then
        cat "$HISTORIC_CRL_CHAIN_FILE"
        ERROR_INFO=$(cat "$ERROR_INFO_FILE")
        echo_warning "Token from $TSA_URL in commit $COMMIT_HASH is invalid since TSA certificate has not been valid at the time the timestamp was created: $ERROR_INFO"
        ((NUM_INVALID++))
        continue          
      fi

      #now check that for each certificate in the trust chain a currently valid CRL can be found AND that
      #each of the certificates either hasn't been revoked OR it has been revoked and the revocation entry contains the reasonCode
      #extension and the reason code is one of unspecified (0), affiliationChanged (3), superseded (4) or cessationOfOperation (5) (see chapter 4 of https://www.ietf.org/rfc/rfc3161.txt)
      local MOST_CURRENT_CRL_CHAIN_FILE="$TMP_DIR"/"$SIGNING_CERT_ID".crl
      if ! download_crls_for_chain "$CERT_CHAIN_FILE" "$MOST_CURRENT_CRL_CHAIN_FILE"; then
        echo_warning "Current CRLs for token could not be downloaded. Will try to use most recent CRL in LTV store".
        if ! git show HEAD:"$CRL_CHAIN_FILE" > "$MOST_CURRENT_CRL_CHAIN_FILE"; then
          echo_warning "Token from $TSA_URL in commit $COMMIT_HASH could not be validated since no currently valid CRL data could be found."
          ((NUM_INVALID++))
          continue
        fi
      fi
      #expand cert chain and crl chain into individual files
      #remove files from previous runs
      rm -f "$TMP_DIR"/*.extracted_cert.pem
      rm -f "$TMP_DIR"/*.extracted_crl.pem
      cat "$CERT_CHAIN_FILE" \
      | awk '/-----BEGIN CERTIFICATE-----/ { i++; } /-----BEGIN CERTIFICATE-----/, /-----END CERTIFICATE-----/ \
      { print > tmpdir i ".extracted_cert.pem" }' tmpdir="$TMP_DIR/"
      cat "$MOST_CURRENT_CRL_CHAIN_FILE" \
      | awk '/-----BEGIN X509 CRL-----/ { i++; } /-----BEGIN X509 CRL-----/, /-----END X509 CRL-----/ \
      { print > tmpdir i ".extracted_crl.pem" }' tmpdir="$TMP_DIR/"
      #iterate over extracted certificates (first is signing certificate, last is self-signed root)
      while ls "$TMP_DIR"/*.extracted_cert.pem &> "$OUT_STREAM" && read EXTRACTED_CERT; do
        if ! openssl verify -CApath "$CA_PATH" -CRLfile "$MOST_CURRENT_CRL_CHAIN_FILE" \
                            -crl_check -untrusted "$CERT_CHAIN_FILE" "$EXTRACTED_CERT" 1> "$OUT_STREAM" 2> "$ERROR_INFO_FILE"; then
          ERROR_INFO=$(cat "$ERROR_INFO_FILE")
          local ERROR_NUMBER=$(echo -n "$ERROR_INFO" | awk '/depth lookup/;' | sed 's/error //' | sed 's/ at.*//')
          #local ERROR_DEPTH=$(cat error.txt | awk '/depth lookup/;' | sed 's/.*at //' | sed 's/ depth lookup.*//')
          #error number must be
          local X509_V_ERR_CERT_REVOKED=23
          if [ "$ERROR_NUMBER" -ne "$X509_V_ERR_CERT_REVOKED" ]; then
            echo_warning "Token from $TSA_URL in commit $COMMIT_HASH could not be validated since certificate validity could not be verified. Error: $ERROR_INFO."
            ((NUM_INVALID++))
            continue 2
          else
            #find revocation reason
            local CERT_SERIAL=$(openssl x509 -inform PEM -in "$EXTRACTED_CERT" -noout -serial | sed 's/serial=//')
            local REVOCATION_ACCEPTABLE=false
            local REASON=''
            while ls "$TMP_DIR"/*.extracted_crl.pem &> "$OUT_STREAM" && read EXTRACTED_CRL; do
              REASON=$(openssl crl -inform PEM -in "$EXTRACTED_CRL" -noout -text | awk '/$"CERT_SERIAL"/{f=1; next} f && /Serial Number:/{f=0} f && /CRL Reason Code:/{g=1; next} g {print; exit}' | sed 's/ *//')
              if [ -z "$REASON" ]; then
                continue
              fi
              #acceptable reasons: see chapter 4 of RFC3161
              if [[ "$REASON" == "Unspecified" || "$REASON" == "Affiliation Changed" || "$REASON" == "Superseded" || "$REASON" == "Cessation Of Operation" ]]; then
                REVOCATION_ACCEPTABLE=true
                break
              fi
            done <<< $(ls "$TMP_DIR"/*.extracted_crl.pem 2> "$OUT_STREAM")
            if [ "$REVOCATION_ACCEPTABLE" != true ]; then
              if [ -z "$REASON" ]; then
                REASON="Certificate revoked without reasonCode extension."
              fi
              echo_warning "Token from $TSA_URL in commit $COMMIT_HASH is invalid since certificate was revoked for the following reason: $REASON"
              ((NUM_INVALID++))
              continue 2
            fi
          fi
        fi
      done <<< $(ls "$TMP_DIR"/*.extracted_cert.pem 2> "$OUT_STREAM")
      #token is valid
      ((NUM_VALID++))
    fi
  done <<< $(ls "$TMP_DIR"/*.extracted_token.pem 2> "$OUT_STREAM")
  local NUM_PROCESSED=$(( $NUM_VALID + $NUM_INVALID + $NUM_SKIPPED ))
  #assert that all extracted timestamps have been processed
  if [ "$NUM_PROCESSED" -ne "$NUM_EXTRACTED" ]; then
    echo_error "Assetion failed NUM_PROCESSED==NUM_EXTRACTED"
    return 1
  fi
  if [ "$NUM_VALID" -eq 0 ] && [ "$NUM_INVALID" -eq 0 ]; then
    #this commit does not contain timestamp tokens.
    return 0
  elif [ "$NUM_VALID" -gt 0 ]; then
    if [ "$NUM_INVALID" -gt 0 ]; then
      echo_warning "Warning: While commit $COMMIT_HASH contains $NUM_VALID valid timestamp tokens and thus is considered proppely timestamped, it also contains $NUM_INVALID invalid timestamp tokens."
    fi
    echo_info "Commit $COMMIT_HASH contains $NUM_VALID valid timestamp tokens."
    return 0
  fi
  echo_error "All $NUM_INVALID timestamp tokens in commit $COMMIT_HASH are invalid."
  return 1
}

# Recursive function to validate all ancestors of commit
# param1: commit hash
# returns: 0 if the validation of the commit and all its ancestors succeeded
validate_commit_and_parents() {
  local COMMIT_HASH="$1"
  log "validate_commit_and_parents for $COMMIT_HASH"
  
  local ALL_PASSED=true
  if ! validate_commit "$COMMIT_HASH"; then
    ALL_PASSED=false
  fi
  local PARENTS=$(git cat-file -p "$COMMIT_HASH" | awk '/^$/{exit} /parent/ {print}' | sed 's/parent //')
  #iterate over all parents of commit
  if [ ! -z "$PARENTS" ]; then
    while read PARENT_HASH; do
      if ! validate_commit_and_parents "$PARENT_HASH"; then
        ALL_PASSED=false
      fi
    done <<< $(echo -n "$PARENTS")
  fi
  if [ "$ALL_PASSED"=true ]; then
    return 0
  fi
  return 1
}

OBJECT="$1"
if [ -z "$OBJECT" ]; then
  OBJECT="HEAD"
fi
COMMIT_HASH=$(git rev-parse "$OBJECT")
if [ -z "$COMMIT_HASH" ]; then
  echo_error "Invalid rev $OBJECT"
  return 1
fi

echo_info "Checking repository integrity..."
#check git repository integrity
if ! git fsck --full --strict --no-progress --no-dangling "$COMMIT_HASH"; then
  echo_error "git fsck failed. This means the repository is in a corrupted state and cannot be validated. Restore corrupt files from a backup or remote repository."
  exit 1
fi

echo_info "Validating timestamps. This may take a while..."
if validate_commit_and_parents "$COMMIT_HASH"; then
  echo_info "Validation OK: All timestamped commits in the commit history of $COMMIT_HASH contain at least one valid timestamp."
  exit 0
else
  echo_error "Validation Failed: There are timestamped commits in the commit history of $COMMIT_HASH which do not contain any valid timestamps."
  exit 1
fi