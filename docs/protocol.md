# Safeboot.dev Enrollment, Attestation, and Proof-of-Possession Protocols

This document descrives the Safeboot.dev enrollment and attestation protocols.

Both of these protocols are intended to run over HTTP POSTs (HTTPS is needed
for enrollment, but is not needed for attestation) with no particular URI
local-part, query parameters, request headers, or response headers.  For
attestation the request and response bodies are uncompressed tarballs.

## Goals

 - specification
 - security review

# Intended Uses

Safeboot.dev enrollment and attestation are currently intended mainly for these
purposes:

 - delivery of a symmetric key (which we call the `rootfskey`) for local
   storage encryption at install time and at every boot event

 - delivery of host credentials at every boot, such as:

    - PKIX certificates for TLS and/or IPsec
    - Kerberos keys ("keytabs")
    - OpenSSH host keys and certificates
    - service account tokens of various kinds

Currently Safeboot.dev enrollment and attestation supports mainly servers.

Servers are expected to be unable to boot in the absence of attestation.

We expect to always PXE boot such servers.

# Enrollment vs Attestation

The Safeboot.dev attestation protocol relies on state created at enrollment
time.

Enrollment is the act of creating state binding a device's TPM and a name for
that device, as well as creating any secrets that that device may repeatedly
need in the environment it will be used in.

For example, a server in a corporate environment may need:

 - secret keys for local storage encryption
 - credentials for network protocols, such as:
    - OpenSSH server keys and certificates
    - TLS server certificates
    - Kerberos keys for host-based service names
    - service account tokens
    - etc.

The separation of enrollment and attestation is motivated by:

 - privilege separation considerations

   We'd like to isolate any issuer credentials to as few systems as possible,
   while allowing the attestation service to be widely replicated.

   Because enrollment is a low-frequency event, while attestation a
   high-frequency event, we can have fewer enrollment servers and more
   attestation servers.  Then we can isolate issuer credentials by plaing them
   only on enrollment servers.

 - database replication and write concurrency considerations

   Having state created and manipulated mainly or only at enrollment servers
   allows us to replicate the enrollment database to attestation servers as a
   read-only database.

   Together with the low frequency of enrollment events this frees us from
   having to address concurrent database updates at this time, at the cost of
   having primary/secondary enrollment server roles.

It is conceivable that the attestation service could support trust-on-first-use
(TOFU) enrollment feature, however, for the moment, we do not implement such a
feature.

## Enrollment Protocol

The enrollment protocol takes two inputs from the client:

 - a desired device name (hostname)
 - the device's TPM's endorsement public key (`EKpub`), either in
   `TPM2B_PUBLIC` or `PEM` formats

These are delivered as an HTML form over an HTTPS POST.  User authentication
and authorization may be required if only certain users should be allowed to
enroll devices.

The enrollment server ensures that the creation of the binding of device name
and `EKpub` is made atomically.  In a putative future where multiple enrollment
servers can concurrently create these bindings, a conflict resolution mechanism
may be used to resolve conflicts.

The enrollment server will also provision the device with any number of secrets
and metadata of various kinds that will be transported to the device during
attestation.

The enrollment protocol is a one round trip protocol:

```
Client->Server: HTTP POST /enroll w/ EKpub and desired device name
Server->Client: 200, 401, 403, or 409
```

### Types of Secrets and Metadata Provisioned

Various types of long-term secrets and metadata can be provisioned to an
enrolled device:

 - configuration
 - symmetric keys (or passphrase) for local storage encryption
 - private keys and PKIX certificates for them (client, server) for TLS, IPsec, etc.
 - Kerberos keys ("keytab")
 - service account tokens
 - IPsec keys for manually keyed SAs
 - etc.

These are configurable as `genprog`s for the `sbin/attest-enroll` program.

All these secrets are encrypted to the device's TPM's `EKpub` and also
encrypted -separately- to the public keys of configured escrow agents for,
e.g., break-glass recovery.

### Storage of Secrets: Encrypted to Device `EKpub`

All these secrets are encrypted to the device's TPM's `EKpub`, each with a
configurable "policy".  Two mechanisms can be used for this, the "WK" and "TK"
mechanisms.

A policy is a TPM 2.0 extended policy, and will be enforced by the device's TPM
when called to decrypt one of these secrets.

The default policy for the `rootfs` key (a symmetric key for local storage
encryption) is that the platform configuration register (PCR) #11 must have the
initial value (all zeros), with the expecation that the attestation client will
immediately extend PCR #11 so that the TPM will not again decrypt the same
ciphertext unless the device reboots.

Policies are configurable for each secret type.

### Escrow

Encryption to escrow agents is done using either raw RSA public keys (in `PEM`
format, for software and HSM escrow agents) or public keys in `TPM2B_PUBLIC`
form (for TPM-based escrow agents).

### Encryption Details

To encrypt a secret the enrollment server:

1. creates a random AES-256 key
2. uses confounded AES-256-CBC-HMAC-SHA-256:
   a. uses AES-256 in cipher block chaining (CBC) mode with
       - all-zero IV
       - confounding (a cipherblock's worth of entropy prepended to the plaintext)
       - padding
   b. appends an HMAC-SHA-256 digest of the resulting ciphertext

The padding is per-OpenSSL (if the plaintext is a whole multiple of 16 bytes
then 16 bytes of zeros are added, else as many bytes are appended to bring the
plaintext size to a whole multiple of 16 bytes, with the last byte set to the
count of padding bytes).

"Confounding" consists of prepending to the plaintext a cipherblock's worth (16
bytes) of randomly generated bits.  This causes the ciphertext resulting from
the encryption of the "confounder" to function as the real, non-zero IV for the
plaintext.

This is very similar to the Kerberos cryptosystem, which differs only in that
CTS (ciphertext stealing mode) is used instead of CBC to avoid the need to pad
the plaintext.

The primary reason for using this construction is that it is implemented in
Bash with OpenSSL 1.x tooling, and OpenSSL 1.x tooling does not provide solid
authenticated encryption constructions in its command-line tools.

The resulting ciphertexts are stored as-is in the enrollment DB.

The per-secret AES-256 keys are encrypted to the device's TPM's EKpub, and to
the escrow agents.

Decryption of confounded AES-256-CBC-HMAC-SHA-256 ciphertexts is as follows:

 - compute the HMAC-SHA-256 MAC of the ciphertext (excluding the MAC in the
   ciphertext)
 - constant-time compare the computed MAC to the MAC in the ciphertext
    - if these do not match, fail
 - decrypt the ciphertext (excluding the MAC) with AES-256 in CBC mode
 - discard the first block of the resulting plaintext (the confounder)
 - examine the last byte of the plaintext and drop the indicated amount of
   padding

### Encryption to TPM `EKpub`: WK Method

1. A well-known key (`WK`) is loaded into a software TPM using
   `TPM2_LoadExternal()` with the desired policy's `policyDigest`.

2. `TPM2_MakeCredential()` is called with these input parameters:
    - the `WKpub` (the loaded WK) as the `objectName` input parameter,
    - the device's `EKpub` as the `handle` input parameter,
    - and the AES-256 symmetric key as the `credential` input parameter (the
      plaintext).

The outputs of `TPM2_MakeCredential()` (`credentialBlob` and `secret`) are the
ciphertext of the AES-256 key encrypted to the TPM's `EKpub`.

The details of what `TPM2_MakeCredential()` does are described in the [TCG TPM
2.0 Library part 1: Architecture, section 24 (Credential
Protection)](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf).

Essentially `TPM2_MakeCredential()` consists of RSA encryption with a plaintext
that binds the cryptographic name of the "activation object" (which in our case
is the `WK` into the ciphertext.  The cryptographic name of an object is a
digest of its "public area", which includes its public key (for asymmetric
keys, which the `EK` is), attributes, `authValue`, and `authPolicy` (the
`policyDigest` of a policy).

### Decryption: WK Method

Decryption is done by calling `TPM2_ActivateCredential()` on the TPM that has
the `EK` corresponding to the `EKpub`.  Critically, the TPM will refuse to
"activate" the credential (i.e., decrypt the ciphertext) unless the caller has
satisfied the WK's `authPolicy` (if set).

To decrypt, access to the TPM identified by the `EKpub` is needed.  The process
is as follows:

 - call `TPM2_LoadExternal()` the well-known key, with the desired
   `authPolicy`, if any
 - call `TPM2_StartAuthSession()` to create a policy session for the `EK`
 - call `TPM2_PolicySecret()` to obtain access to the `EK`
 - call `TPM2_StartAuthSession()` to create a policy session for the `WK` (if
   one was set)
 - call the policy commands on the `WK` session handle to satisfy its policy
   (if one was set)
 - call `TPM2_ActivateCredential()` with the loaded `WK` as the
   `activateHandle` and its corresponding policy session, the `EK` as the
   `keyHandle` and its corresponding policy session, and the ciphertext
   (`credentialBlob` and `secret`) as input parameters

Then, once the AES-256 key is decrypted, the confounded AES-256-CBC-HMAC-SHA256
ciphertext is decrypted as described above.

### Encryption to TPM `EKpub`: TK Method

1. create an RSA key-pair in software
2. encrypt the AES-256 key to the RSA public key using OEAP with any software
3. use a software TPM to encrypt the RSA private key from (1) to the `EKpub` of
   the target TPM using `TPM2_Duplicate()`, setting the desired policy's
   `policyDigest` as the intended `authPolicy` of the RSA key as it will be
   when loaded by the target TPM
4. the ciphertext then consists of a) the ciphertext from encryption to the RSA
   public key, b) the outputs of `TPM2_Duplicate()`

### Decryption: TK Method

Decryption is done by calling `TPM2_Import()` and `TPM2_Load()` to import and
load the output of `TPM2_Duplicate()`, decrypting the key with the TPM's `EK`
in the process, then by calling `TPM2_RSA_Decrypt()` to decrypt the AES-256
key.

Then, once the AES-256 key is decrypted, the confounded AES-256-CBC-HMAC-SHA256
ciphertext is decrypted as described above.

### Break-Glass

Break-glass recovery consists of:

1. replacing a device's TPM or a device including its TPM (but not the device's
   local storage),
2. decrypting the secrets (AES-256 keys) stored in the enrollment DB using an
   escrow agent,
3. encrypting those to the new TPM's `EKpub`,
4. and replacing the corresponding ciphertexts in the enrolled device's entry
   in the enrollment DB.

## Attestation Protocol

To attest, a client first generates an attestation key (`AK`), a signing key
created under the `EK` in the TPM's endorsement hierarchy.  This object must
have the `stClear` attribute set, which means that the TPM will refuse to
reload or re-create this `AK` if the TPM is reset (which happens when the host
device reboots).  Then it creates a "quote" of all the PCRs, with the quote
signed with the `AK`.

The attestation protocol consists of an HTTP POST (HTTPS not required) with a
request body consisting of a tarball of the following items:

 - `ek.crt` -- the `EKcert`, that is, the PKIX certificate for the TPM's
   endorsment key (EK) as provisioned by the TPM's vendor

   (this is optional, present only if the TPM has an `EKcert`)

 - `ek.pub` -- the `EKpub` in `TPM2B_PUBLIC` format

 - `ak.pub` -- the `TPM2B_PUBLIC` representation of the `AK`

 - `quote.out`, `quote.sig`, and `quote.pcr` -- the outputs of `TPM2_Quote()`
   using the `AK`

 - `nonce` -- a timestamp as seconds since the Unix epoch

 - `eventlog` -- if possible, this is the TPM PCR eventlog kept by the UEFI
   BIOS

 - `ima` -- if possible, this is the Linux IMA log

The attestation server then:

 - looks up the device's enrollment DB entry by the given `EKpub`
 - examines the `ak.pub` to ensure that it has the desired attributes
 - verifies that the eventlog matches the PCRs
 - verifies that the digests that appear in the eventlog are acceptable, or
   that the PCRs match "golden PCRs"
 - examines the `nonce` to verify that it is a recent timestamp

If all the validation steps succeed, then the attestation server:

 - constructs a tarball of the device's enrollment DB entry's items,
 - encrypts that tarball in an ephemeral AES-256 session key,
 - encrypts the ephemeral AES-256 session key to the device's TPM's `EKpub`
   using `TPM2_MakeCredential()` with the `AKpub`'s name as the `objectName`
   and the `EKpub` as the `handle`

In the successful case, then, the response body is a tarball consisting of:

 - `credential.bin` -- `credentialBlob` and `secret` output parameters of the
   `TPM2_MakeCredential()` call
 - `cipher.bin` -- the ciphertext of a tarball of the device's enrollment DB
   entry, encrypted with the AES-256 session key using confounded
   AES-256-CBC-HMAC-SHA-256 as described above.
 - `ak.ctx` (as provided by the client, sent back)

Note that we use the server uses `TPM2_MakeCredential()` to construct the
response, much like the "WK method" of encrypting secrets, with these
differences:

 - the client's ephemeral `AKpub` is used to construct the `objectName` input
   parameter,

   (This means that if the client reboots it will not be able to decrypt this
   response with `TPM2_ActivateCredential()` because the `AK` had `stClear`
   set, which means it cannot be recovered if the TPM is reset.)

 - the `objectName` does not involve a `policyDigest`

 - the ciphertext is not a long-term stable ciphertext but one made with an
   ephemeral AES-256 session key.

The client can only decrypt and recover the AES-256 session key IFF it has a
TPM with the corresponding `EK` and `AK` loaded.

Having recovered the AES-256 session key, the client can decrypt the tarball of
the client's long-term secrets and metadata, where the secrets are encrypted to
the client's TPM using the WK or TK methods.  The client can then decrypt the
secrets whose policies it can satisfy.

The client is expected to immediately extend PCR #11 so that long-term secrets
whose policies expect PCR #11 to be in its initial state (all zeros) cannot
again be decrypted with the client's TPM without first rebooting.

## Proof-of-Possession Protocol

TBD (not yet designed or implemented)

## Enrollment Database

Currently the `sbin/attest-enroll` program uses the filesystem to access the
enrollment DB.  Configurable hooks allow a site to convert the filesystem
representation to other representations.  One upcoming use will be to use a
`CHECKOUT` hook to fetch a client's current entry from the DB and a `COMMIT`
hook to commit a client's new current entry in the DB, using a Git repository
to encode the client's entry as left on the filesystem by `sbin/attest-enroll`.

### Enrollment Database Schema

Client entry filesystem layout:

 - `$DBDIR/${ekhash:0:2}/${ekhash}/`

   The directory for the device is named after its `EKpub`'s SHA-256 digest.

   (An `EKpub` is in `TPM2B_PUBLIC` format, per the TPM specifications.)

 - `$DBDIR/${ekhash:0:2}/${ekhash}/ek.pub`

   The `EKpub`, in `TPM2B_PUBLIC` format.

 - `$DBDIR/${ekhash:0:2}/${ekhash}/hostname`

   (metadata) Contains the hostname (fully-qualified).


 - `$DBDIR/${ekhash:0:2}/${ekhash}/user-data`

   (metadata) Contains some YAML description of the device's enrollment.

 - For each type of secret:

    - `$DBDIR/${ekhash:0:2}/${ekhash}/${secret_name}.enc`

      This is the secret itself, encrypted in confounded
      AES-256-CBC-HMAC-SHA-256, with a unique symmetric key (see item below).

    - `$DBDIR/${ekhash:0:2}/${ekhash}/${secret_name}.symkeyenc`

      This is the AES-256 key used to encrypt the the previous item, itself
      encrypted to the device's TPM's `EKpub`.  (In this case using the "WK"
      method.)

    - `$DBDIR/${ekhash:0:2}/${ekhash}/${secret_name}.policy`

      Contains a SHA-256 digest of the TPM policy used to encrypt the previous
      item.

    - `$DBDIR/${ekhash:0:2}/${ekhash}/escrow-${escrow_agent_names[0]}.symkeyenc`
    - `$DBDIR/${ekhash:0:2}/${ekhash}/escrow-${escrow_agent_names[1]}.symkeyenc`
    - ..
    - `$DBDIR/${ekhash:0:2}/${ekhash}/escrow-${escrow_agent_names[$n]}.symkeyenc`

      These are the `${secret_name}.symkey` encrypted to escrow agents `0`,
      `1`, `..`, and `n`, if any such are defined.

 - Secret and metadata types:

    - `hostname` (metadata; see above)
    - `user-data` (metadata; see above)
    - `cert-key.pem` (secret; a private key for a certificate)
    - `cert.pem` (metadata; a certificate for `cert-key.pem` naming `hostname`)
    - `keytab` (secret; long-term secret keys for Kerberos principals for
      `hostname`, mainly for the `host` service name)
    - ...

# Site-local Customization

Things that may vary locally:

 - enrollment service URI

   Naturally, different companies / users of Safeboot.dev will have different
   enrollment service URIs, but they may even vary by datacenter, by rack, by
   client OS, etc.

 - attestation service URIs

   Ditto.  Also, attestation service URIs must differ from enrollment service
   URIs.

 - enrollment server hooks:

    - `genprog`s
    - `CHECKOUT` hook
    - `COMMIT` hook
    - (TBD) add `VALIDATE` hook for validating `EKcert`/`EKpub`

# Implementation Considerations

The entire client side of the Safeboot.dev attestation protocol is implemented
in Bash using native command-line tools to interact with the TPM and to perform
software cryptographic operations, such as tpm2-tools and OpenSSL.

The reason for the client side being implemented mostly in Bash is that we
intend to use PXE booting, and we need the Linux initramfs image to be small.
Using Bash and standard command-line tools (typically coded in C) allows the
Linux initramfs image that must contain them to be small.

Most of the server side of enrollment and attestation is also implemented in
Bash, with some in Python.

# Security Considerations

Two facts make the attestation database very sensitive, both to write and to
read:

> The attestation server response is not authenticated.  That is, it is not
> signed.  This means that an attacker can impersonate an attestation server
> and feed the client arbitrary secrets and metadata.
>
> The client can, typically, validate some of these items.  For example, the
> `rootfs` key either is capable of decrypting the client's local storage, or
> it is not.  A PKIX certificate will be issued by a trusted CA, or not.  A
> Kerberos "keytab" can be validated by performing a Kerberos AS exchange with
> anonymous PKINIT requesting a ticket for the host's service, and then
> attempting to decrypt that ticket with the key(s) in the keytab.
>
> Metadata, on the other hand, typically cannot be validated cryptographically.
>
> (We should really add signatures, both of each item and of the whole.  But
> note that attesting clients are not in a position to perform revocation
> checks, or even to know what trust anchors to use in some cases!)
>
> Therefore the attestation DB is sensitive for writing: only legitimate
> enrollment servers should have read access.

and

> We rely delivering long-term encrypted secrets super-encrypted such that the
> client must attest its current state is trusted in order to recover its
> encrypted long-term secrets and then decrypt them.
>
> If a client could obtain its encrypted long-term secrets without attesting
> its current state is trusted, then the client could recover those secrets
> without attesting.  We do not want this.
>
> Therefore the attestation DB is sensitive for reading: only legitimate
> attestation servers should have read access.

Therefore we must have strict authorization checks for both, writing and
reading the attestation database.

The enrollment server can implement TOFU enrollment or authenticated and
authorized enrollment.  If the latter, then the enrollment server MUST
authenticate the user enrolling a device, and it MUST check if the user is
authorized to do so (and possibly it must check if the user is authorized to
create devices with names like the proposed name).

We use a single round trip attestation protocol because, if the enrolled device
`EKpub` is really for a TPM (and this MUST have been validated), then the
semantics of `TPM2_ActivateCredential()` and the `AKpub` attribute validation
done by the attestation server, together serve to provide us with all the
guarantees we need that the PCR quote was legitimate.

A proof-of-possession protocol is strictly optional, but it can help provide
alerting.

## `EKpub` Validation

We rely utterly on TPMs enforcing extended policies.  This means that we must
know that some `EKpub` is indeed a TPM's `EKpub`.

### External `EKpub` Validation (Google Compute Environment)

In the Google Compute Environment the Google Shielded VM product allows us to
lookup a device by name and obtain its `EKpub` in `PEM` format.

If authorized users of the enrollment service can be trusted to fetch the
`EKpub` from the Google Shielded VM API, then the enrollment server need not
validate the `EKpub` at all -- the attestation server can just trust the given
`EKpub`.

### `EKpub` Validation using `EK` Certificates

When enrolling bare-metal hardware, as opposed to Google Shielded VMs, we must
either extract the to-be-enrolled device's TPM's `EKpub` manually, and once
more trust and allow only authorized users of the enrollment service to enroll
those, or we must extract the to-be-enrolled device's TPM's `EKcert` and enroll
that so that the enrollment server may validate the client's `EKcert` is issued
by a trusted TPM vendor.

XXX We have yet to implement this.

## Possible Methods of Authentication of Enrolled Secrets and Metadata

As noted above, early in boot, particularly during PXE booting, the attestation
client may not have any reliable way to authenticated enrolled files sent back
by the attestation server.  We would like to find methods of authenticating
those files.

One possibility would be to store a digest of a public signing key in an NV
index on the client's TPM, add that public key to the tarball sent back to the
client, then have the client check that every file is signed by that key.  This
can be generalized to a PKI.  The main problem with this approach is: how to
write that NV index in time for the first attestation?  The only plausible
answers may be a) TOFU, or b) booting from trusted media (flashdrive).

Another possiblity would be to enroll not just the device's `EKcert`/`EKpub`,
but also a signature of an enrollment server authentication public key made
with a signing key created using a hard-coded template and
`TPM2_CreateLoaded()`.  This, however, would require two round trips for
enrollment: one to fetch an authentication public signing key to sign, then one
to enroll.  The attestation response would then also carry a) the signature of
the authentication key, b) signatures of all metadata and encrypted secrets
made with the authentication private key.  The client would then be able to
authenticate attestation server responses.

In any case, authentication key rotation would be difficult.  Indirection via
intermediate keys (PKI-style) would help.

# TODO

 - add sample `CHECKOUT` and `COMMIT` hooks for using Git
 - add scripts for setting up Git repository for enrollment database
 - add `EKcert` support to enrollment
 - add `VALIDATE` hook for enrollment
 - add sample `VALIDATE` hooks for enrollment that use Google Shielded VM,
   `EKcert` validation, etc.
 - add configuration of trusted TPM vendors (as a set of their CA certificates)
 - add optional authentication mechanism for enrolled data

