# GitTrustedTimestamps
RFC3161 and RFC5816 Timestamping for git repositories.

By using this post-commit hook in a repository and thereby adding secure timestamps to the commits it contains, the repository gains the following properties:
- Authenticity: trusted, non-refutable time when data was commited
- Integrity: protection of the timestamped data as well as the timestamps themselves from tampering without detection
- Timeliness: proof that the time of the digital signature (if used together with PGP signatures) was in fact the actual time
- An evidentiary trail of authenticity for legal sufficiency

# What are RFC3161 and RFC5816 Timestamps

RFC3161 (https://tools.ietf.org/html/rfc3161) and its extension RFC5816 (https://tools.ietf.org/html/rfc5816) are protocol specifications timestamp data using cryptographically secure tokens issued by an external, trusted third party TSA (Time Stamping Authority). By timestamping data this way, it is possible to prove to anyone who trusts this TSA service that the data existed already at the time of timestamping and has not been tampered with ever since. Only a secure hash of the data, without any identification, is being sent to the TSA service, so the data itself remains secret.

# Dependencies

One goal of this project is to only use "vanilla" git features to add the timestamps in order to stay as forward compatible as possible, as well as to not rely on new binaries (which would need to be trusted too). The software is implemented as bash scripts and uses OpenSSL (https://www.openssl.org/) and git itself for all cryptographic computations.

# How to use this software

0. (optional, but recommended) if you're ceating a new repository, it is strongly recommended to use SHA256 hashes (git uses SHA1 by default at the time of writing) by initializing the reopository using `git init --object-format=sha256` (Note: If you want to use a public hosting server such as github for your repository, you should check whether they already support SHA256 repositories).
1. Copy the three bash scripts in the [hooks](hooks/) folder of this project into the .git/hooks folder of the project you want to timestamp.
2. Configure the TSA url you want to use (in this example https://freetsa.org/tsr) using `git config --local timestamping.tsa0.url https://freetsa.org/tsr`
3. You must declare that you trust this TSA by copying the root certificate of that TSA's trust chain into the .git/hooks/trustanchors folder (create it if it doesn't exist yet). The certificate MUST be in PEM format and the filename MUST be "subject_hash.0" where`subject_hash` is what openssl returns for the `--subject_hash` argument for x509 cetificates (https://www.openssl.org/docs/man1.1.1/man1/x509.html).  
**For your convenience, there is the [hooks/trust.sh](hooks/trust.sh) script which will do this for you.** To use it, simply run `.git/hooks/trust.sh https://freetsa.org/tsr` from your Git-Bash and confirm adding the certificate (Note: The certificates stored in .git/hooks/trustanchors are ONLY used to validate timestamp tokens, no other trust is established).
4. (optional) If you want to use multiple TSAs, just set additional urls for tsa1, tsa2 and so on. Make sure that they are all defined consecutively, for example, if you have a url defined for tsa0 and for tsa2, but not for tsa1, then tsa2 will be ignored. Since timestamp tokens will become forever invalid should a TSA's private key leak, using at least two trusted TSAs is a good strategy to protect against this unlikely eventuality (see chapter 4. "Security Considerations" of RFC3161 specification).
5. (optional) By default, a commit will fail if a timestamp token cannot be retrieved. If you want to make timestamping optional for a certain tsa, you can set `git config --local --type=bool timestamping.tsa0.optional true`. If `optional` is set to true and a timestamping token cannot be retrieved, you will receive a warning but the commit will be created nevertheless.

# How are timestamps added to commits

For each commit that is being timestamped, an additional *timestamping commit* is created, for which the commit that is being timestamped is the direct parent. The hash that is contained in the timestamp token corresponds to the git hash of the commit being timestamped. The timestamping token (one for each TSA for which a timestamp was retrieved) is then added in PEM encoding (plus some info about the token in readable form) as a trailer to the commit message of the *timestamping commit*. Chosing this design to add the timestamps has several advantages:
- The commit hash always depends on the entire data of that commit (including the pgp signature that commit is signed with) and its history, meaning that not a single bit of data being committed (or the history it depends on) could be changed without creating a completely different commit hash.
- It is most likely the most forward-compatible option. If new commit headers or other commit data will be added to git in the future, they will most likely also be captured by the commit hash.
- By storing the tokens inside the commit message, which is hashed itself, subsequent commits will *seal* these timestamps, making it impossible to "lose" them, which gives the timestamping of the repository a *non-repudiation* property (https://en.wikipedia.org/wiki/Non-repudiation), meaning it will be impossible to "rewrite history" unnoticed.
- Since newer timestamps *seal* older timestamps (i.e. the older timestamps are part of what is being timestamped), this protects old timestamps from becoming invalid in some situations. For example: Say in 2020 all commits are timestamped using a TSA that uses "certificateA" to sign its timestamps. Then in 2021 a TSA is used which uses "certificateB" to sign its timestamps. Then in 2022 the private key of "certificateA" leaks. Normally, if a TSA's private key leaks, all old timestamps become invalid and can't be trusted anymore (because the private key could be used to "backdate" data) - however, since in this case the timestamps of 2021, which are signed with the still trusted "certificateB" *sealed* the older timestamps, these old timestamps can still be considered valid, since they were provably created before the "certificateA" private key leaked. The same applies to old timestamps becoming invalid for example due to the algorithm used for them not being deemed secure anymore.

Additionally to retrieving TSA tokens and timestamping the commits with them, the post-commit hook will also validate these tokens first to ensure that only valid, trusted time-stamp tokens are added. It does so by validating that:
- The received token corresponds to the request (a nonce is used for this).
- The token is valid and trusted.
- All certificates in the trust-chain up to a trusted anchor (stored in .git/hooks/trustanchors) are valid and have not been revoked (checked by downloading and checking CRLs for all certificates).

# LTV data:

Additionally to the bare timestamp tokens stored in the commit message as trailers, the *timestamping commit* also adds revisioned files to the .timestampltv folder. If the timestamps should be evaluated many years in the future when the entire certificate chains of tokens for example are not available anymore, this *Long Term Validation* data will facilitate validating the tokens. For each *timestamping commit* two files will be stored:
1. .timestampltv/certs/issuer_hash.cer: This file contains the entire trust chain of the TSA certificate in PEM format. In most cases this file will not change for subsequent timestamp tokens, so no additional data is added to the repository (the file content only changes if the TSA changes its signing certificate).
2. .timestampltv/crls/issuer_hash.crl: This file contains CRL responses in PEM format for all certificates in the trust chain at the time of timestamping.

The `issuer_hash` for both files corresponds to the ESSCertID or ESSCertIDv2 hash with which the token identifies its issuer certificate.