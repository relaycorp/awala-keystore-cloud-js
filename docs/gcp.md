---
nav_order: 1
permalink: /gcp
---
# Google Cloud Platform (GCP)

The GCP key store only uses [Cloud KMS](https://cloud.google.com/kms), which is serverless and fully managed by Google, so you don't need to worry about up/down scaling or uptime/performance monitoring. We protect sensitive cryptographic material with Cloud KMS as follows:

- Awala identity key pairs (used for digital signatures) are stored in and fully managed by Cloud KMS. Cloud KMS performs all the cryptographic operations. Neither this library nor the app using it can access the private key.
- Awala session key pairs (used for encryption) are stored in MongoDB, encrypted with a customer-managed KMS key and using [Additional Authenticated Data (AAD)](https://cloud.google.com/kms/docs/additional-authenticated-data) for extra security. We wish these too were stored in KMS, but [KMS doesn't currently support the algorithms we require](https://issuetracker.google.com/issues/231334600).

As of this writing, the library complies with all of [KMS' data integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines).

All the metadata about the keys are stored on MongoDB.

## Resources

You should provision the following in GCP:

- A KMS key ring containing the following keys:
  - An **asymmetric signing key** (RSA-PSS, 2048 or 4096 bits, and SHA-256 or SHA-512). Do not provision a key version as it wouldn't be used. The library will use `RSA_SIGN_PSS_2048_SHA256` by default.
  - A **symmetric encryption key**, along with a key version.
- A service account.

This library will provision and manage the key versions in the KMS signing key.

## IAM Permissions

### Private key store

Identity keys:

- Create identity key pair:
  - `cloudkms.cryptoKeys.get` on the KMS signing key.
  - `cloudkms.cryptoKeyVersions.create` on the KMS signing key.
  - `cloudkms.cryptoKeyVersions.viewPublicKey` on the newly-created KMS signing key version.
- Retrieve identity key: None.
- Sign with identity key:
  - `cloudkms.cryptoKeyVersions.useToSign` on the KMS signing key version.
  - `cloudkms.cryptoKeyVersions.viewPublicKey` on the KMS signing key version, when issuing a certificate.

Session keys:

- Create session key pair:
  - `cloudkms.cryptoKeyVersions.useToEncrypt` on the KMS encryption key.
- Retrieve session key pair:
  - `cloudkms.cryptoKeyVersions.useToDecrypt` on the KMS encryption key.
- Encrypt or decrypt with key pair: No additional permissions needed once key pair is in memory.

## Recommendations

- [Rotate KMS encryption key versions periodically](https://cloud.google.com/kms/docs/key-rotation).
- Monitor your Cloud KMS quotas, to request increases when/if necessary.

## Limitations

- The app server must be located in the same project and region.
