# GitTrustedTimestamps

RFC3161 and RFC5816 Timestamping for git repositories.

By using this post-commit hook in a repository and thereby adding secure timestamps to the commits it contains, the repository gains the following properties:
- Authenticity: trusted, non-refutable time when data was commited
- Integrity: protection of the timestamped data as well as the timestamps themselves from tampering without detection
- Timeliness: proof that the time of the digital signature (if used together with PGP signatures) was in fact the actual time
- An evidentiary trail of authenticity for legal sufficiency

# How to use this software

0. (optional, but recommended) If you're ceating a new repository, it is strongly recommended to use SHA256 hashes (git uses SHA1 by default at the time of writing) by initializing the reopository using `git init --object-format=sha256` (Note: If you want to use a public hosting server such as github for your repository, you should check whether they already support SHA256 repositories). For more information, see https://git-scm.com/docs/hash-function-transition/
1. Copy the three bash scripts in the [hooks](hooks/) folder of this project into the .git/hooks folder of the project you want to timestamp.
2. Configure the TSA url you want to use (in this example https://freetsa.org/tsr) using `git config --local timestamping.tsa0.url https://freetsa.org/tsr`
3. You must declare that you trust this TSA by copying the root certificate of that TSA's trust chain into the .git/hooks/trustanchors folder (create it if it doesn't exist yet). The certificate MUST be in PEM format and the filename MUST be "subject_hash.0" where`subject_hash` is what openssl returns for the `--subject_hash` argument for x509 cetificates (https://www.openssl.org/docs/man1.1.1/man1/x509.html).  
**For your convenience, there is the [hooks/trust.sh](hooks/trust.sh) script which will do this for you.** To use it, simply run `.git/hooks/trust.sh https://freetsa.org/tsr` from your Git-Bash and confirm adding the certificate (Note: The certificates stored in .git/hooks/trustanchors are ONLY used to validate timestamp tokens, no other trust is established).
4. (optional) If you want to use multiple TSAs, just set additional urls for tsa1, tsa2 and so on. Make sure that they are all defined consecutively, for example, if you have a url defined for tsa0 and for tsa2, but not for tsa1, then tsa2 will be ignored. Since timestamp tokens will become forever invalid should a TSA's private key leak, using at least two trusted TSAs is a good strategy to protect against this unlikely eventuality (see chapter 4. "Security Considerations" of RFC3161 specification).
5. (optional) By default, a commit will fail if a timestamp token cannot be retrieved. If you want to make timestamping optional for a certain tsa, you can set `git config --local --type=bool timestamping.tsa0.optional true`. If `optional` is set to true and a timestamping token cannot be retrieved, you will receive a warning but the commit will be created nevertheless.

From now on, every `git commit` will tigger an additional commit that securely timestamps this commit.

# What are RFC3161 and RFC5816 Timestamps

RFC3161 (https://tools.ietf.org/html/rfc3161) and its extension RFC5816 (https://tools.ietf.org/html/rfc5816) are protocol specifications timestamp data using cryptographically secure tokens issued by an external, trusted third party TSA (Time Stamping Authority). By timestamping data this way, it is possible to prove to anyone who trusts this TSA service that the data existed already at the time of timestamping and has not been tampered with ever since. Only a secure hash of the data, without any identification, is being sent to the TSA service, so the data itself remains secret.

# Alternatives

Before writing this software, I evaluated alternatives available at the time of writing (Feb 2021). I will briefly list and discuss my findings here to outline the differences.

- There is a stackoverflow question (https://stackoverflow.com/questions/11913228/how-can-i-use-rfc3161-trusted-timestamps-to-prove-the-age-of-commits-in-my-git) and subsequently posted code review (https://codereview.stackexchange.com/questions/15380/adding-trusted-timestamps-to-git-commits):  
This script allows to manually create timestamps for revisions and store them in git-notes. This was not sufficient for me since having timestamps stored in git-notes makes them "cryptographically dangling" in the sense that the timestamped repository does not depend on them (meaning that they can be "lost" without being noticed). This may be the preferred solution for someone who just wants to be *able* to prove the time the code was created if he so desires, without creating a repository which is *tamperproof* (and without the benefits discussed further down). Also, the script does not take CRLs into consideration for validation.

- GitLock (https://www.npmjs.com/package/gitlock):  
GitLock adds timestamps as tags, which, like git-notes, also won't make the timestamped repository cryptographically depend on the timestamps themselves and thus offers the same advantages/disadvantages as the script above. It also creates a parallel SHA256 hierarchy (which isn't necessary anymore, since git now provides native SHA256 support) and depends on a Node.js application that must be installed and used manually. This solution may be preferred if the same conditions hold as with the first altenative and additionally SHA256 is required but a public git server which does not yet support native SHA256 commit hashes is used.

- There is [this](https://gitlab.cs.fau.de/CSG/git-rfc3161) fork of git:  
The fork was created as part of a university project to add native support for RFC3161 tokens to git. There is a corresponding discussion in the archived git mailing list (http://git.661346.n2.nabble.com/Adding-RFC-3161-timestamps-to-git-tags-td7650116.html). Since it requires a custom build of git and wasn't adopted by the official repo, I did not further investigate this implementation.

- There is [this](https://www.gwern.net/Timestamping#timestamping-version-control-systems) article discussing timestamping git repositories:  
It is using the OriginStamp (https://originstamp.com/) timestamping service. This solution does not use RFC3161 but instead relies on publication of hashes in public blockchains using the OriginStamp service (which comes with the advantages and disadvantages of blockchain transactions, such as long confirmation times and high fees).

- Zeitgitter (https://pypi.org/project/git-timestamp/)
Zeitgitter seems to use a custom timestamping protocol and rely on developers cross-verifying their timestamps. Since it requires a custom client and server application and does not rely on RFC3161, I did not further investigate this implementation.

# Implementation design

The design goals of this implementation are simplicity (security without obscurity), using only "vanilla" git features to add the timestamps in order to stay as forward compatible as possible, as well as to not rely on new binaries (which would need to be trusted too). The software therefore is implemented as bash scripts and uses OpenSSL (https://www.openssl.org/) and git itself for all cryptographic operations.  
Additionally a goal was that commits will depend on previous timestamps, so that they cryptographically *seal* the older timestamps which makes the repository both tamperproof and protects older timestamps from some forms of invalidation.

# How are timestamps added to commits

For each commit that is being timestamped, an additional *timestamping commit* is created, for which the commit that is being timestamped is the direct parent. The hash that is contained in the timestamp token corresponds to the git hash of the commit being timestamped. The timestamping token (one for each TSA for which a timestamp was retrieved) is then added in PEM encoding (plus some info about the token in readable form) as a trailer to the commit message of the *timestamping commit*. Chosing this design to add the timestamps has several advantages:
- The commit hash always depends on the entire data of that commit (including the pgp signature that commit is signed with) and its history, meaning that not a single bit of data being committed (or the history it depends on) could be changed without creating a completely different commit hash.
- It is most likely the most forward-compatible option. If new commit headers or other commit data will be added to git in the future, they will most likely also be captured by the commit hash.
- By storing the tokens inside the commit message, which is hashed itself, subsequent commits will *seal* these timestamps, making it impossible to "lose" them, which gives the timestamping of the repository a *non-repudiation* property (https://en.wikipedia.org/wiki/Non-repudiation), meaning it will be impossible to "rewrite history" unnoticed.
- Since newer timestamps *seal* older timestamps (i.e. the older timestamps are part of what is being timestamped), this protects old timestamps from becoming invalid in some situations. For example: Say in 2020 all commits are timestamped using a TSA that uses "certificateA" to sign its timestamps. Then in 2021 a TSA is used which uses "certificateB" to sign its timestamps. Then in 2022 the private key of "certificateA" leaks. Normally, if a TSA's private key leaks, all old timestamps become invalid and can't be trusted anymore (because the private key could be used to "backdate" data) - however, since in this case the timestamps of 2021, which are signed with the still trusted "certificateB" *sealed* the older timestamps, these old timestamps can still be considered valid, since they were provably created before the "certificateA" private key leaked. The same applies to old timestamps becoming invalid for example due to the algorithm used for them not being deemed secure anymore.

An altenative design that was considered but dismissed was to include the timestamps right into the commit message of the commit that is being timestamped, in a similar fashion as PGP signatures are added. PGP signatures do this by calculating the commit hash AS-IF the signature was not contained, then sign this hash and then add the signature into the commit header (thereby changing the hash). A similar approach could have been taken with the timestamps, but this would have two serious drawbacks:
1. Since PGP signatues are inserted natively AFTER the commit is generated, the timestamp token could therefore not timestamp the signature (instead, the signature would sign the timestamp, which is not useful).
2. Validation code would need to compute a commit hash AS-IF the timestamp-token was not contained, but also AS-IF any insertions happening AFTER timestamping were not present (at the time of writing, that's only PGP-Signatures. However, since future versions of git may include other additional headers in a similar fashion, this would break current timestamp validation code).

For these reasons, adding timestamps right into the commit that is being timestamped was dismissed, for separate *timestamp commits* are much more likely to be forward compatible with anything git will add to the commit object in the future.

Additionally to retrieving TSA tokens and timestamping the commits with them, the post-commit hook will also validate these tokens first to ensure that only valid, trusted time-stamp tokens are added. It does so by validating that:
- The received token corresponds to the request (a nonce sent in the request is being used for this).
- The token is valid and trusted.
- All certificates in the trust-chain up to a trusted anchor (stored in .git/hooks/trustanchors) are valid and have not been revoked (checked by downloading and checking CRLs for all certificates).

This repository uses the post-commit hook itself, so if you check the commit history of this repository, you will see that each commit is followed by a -----TIMESTAMP COMMIT----- that contains one or more timestamp tokens.  
For example, [this](https://github.com/MrMabulous/GitTrustedTimestamps/commit/a3e7a2a4a280fc03abe51ff70a8bd603837af150) *timestamp commit* timestamps [this](https://github.com/MrMabulous/GitTrustedTimestamps/commit/4f88284a578ba8309269a4d1f2474033fe441e82) regular commit, which is its direct parent. You can see that the "Message data" of the timestamp token is the commit hash 4f88284a578ba8309269a4d1f2474033fe441e82 of the timestamped commit.

# LTV data:

Additionally to the bare timestamp tokens stored in the commit message as trailers, the *timestamping commit* also adds revisioned files to the .timestampltv folder. If the timestamps should be evaluated many years in the future, when the TSA does not exist anymore and the entire certificate chains of tokens for example can't be retrieved anymore, this *Long Term Validation* data will facilitate validating the tokens. For each *timestamping commit* two files are stored:
1. .timestampltv/certs/issuer_hash.cer: This file contains the entire trust chain of the TSA certificate in PEM format (the first certificate being the TSA's signing certificate and the last being the self-signed root). In most cases this file will not change for subsequent timestamp tokens, so no additional data is added to the repository (the file content only changes when the TSA changes its signing certificate).
2. .timestampltv/crls/issuer_hash.crl: This file contains CRL responses in PEM format for all certificates in the trust chain at the time of timestamping. In most cases this file will not change for subsequent timestamp tokens, so no additional data is added to the repository (the file content only changes when the CRL lists referenced by certificate in the trust chain change).

The `issuer_hash` for both files corresponds to the ESSCertID or ESSCertIDv2 hash with which the token identifies its issuer certificate. In general this is the SHA1 hash of the DER encoded issuer certificate for RFC3161 tokens, and some other hash of the DER encoded issuer certificate for RFC5816 tokens (the ESSCertIDv2 of the token specifies the used hashing algorithm).

# Author

- Matthias Bühlmann