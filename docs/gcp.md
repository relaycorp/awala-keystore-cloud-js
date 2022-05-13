---
nav_order: 1
permalink: /gcp
---
# Google Cloud Platform (GCP)

The GCP keystores only use Cloud KMS and Firestore in Datastore mode, both of which are serverless and fully managed by Google, so you don't need to worry about up/down scaling or uptime/performance monitoring.

Sensitive cryptographic material is protected with Cloud KMS as follows:

- Awala identity key pairs (used for digital signatures) are stored in and fully managed by Cloud KMS. Cloud KMS performs all the cryptographic operations. Neither this library nor the app using it can access the private key.
- Awala session key pairs (used for encryption) are stored in Datastore, encrypted with a customer-managed KMS key and using [Additional Authenticated Data (AAD)](https://github.com/relaycorp/awala-keystore-cloud-js/issues/6) for extra security. We wish these too were stored in KMS, but [KMS doesn't currently support the algorithms we require](https://issuetracker.google.com/issues/231334600).

As of this writing, the library complies with all of [KMS' data integrity guidelines](https://cloud.google.com/kms/docs/data-integrity-guidelines).

Datastore is used to store the remaining data.

## Resources

You should provision the following:

- A KMS key ring containing the following keys:
  - An **asymmetric signing key** (RSA-PSS, 2048 or 4096 bits, and SHA-256 or SHA-512). Do not provision a key version as it wouldn't be used. The library will use `RSA_SIGN_PSS_2048_SHA256` by default.
  - A **symmetric encryption key**, along with a key version.
- Firestore configured in Datastore mode.
- GCP service account.

This library will provision and manage the following resources:

- Key versions in the KMS signing key.
- The Datastore kinds `identity_keys` and `session_keys` under the specified namespace.

## Recommendations

- Rotate KMS encryption key versions periodically.
- Monitor your Cloud KMS and Datastore quotas, to request increases when/if necessary.

## IAM Permissions

### Private key store

Identity keys:

- Create identity key pair:
  - `cloudkms.cryptoKeys.get` on the KMS signing key.
  - `cloudkms.cryptoKeyVersions.create` on the KMS signing key.
  - `cloudkms.cryptoKeyVersions.viewPublicKey` on the newly-created KMS signing key version.
  - `datastore.entities.create` on the `identity_keys` kind, under the namespace specified by you.
- Retrieve identity key:
  - `datastore.entities.get` on the `identity_keys` kind, under the namespace specified by you.

  KMS isn't accessed.
- Sign with identity key:
  - `cloudkms.cryptoKeyVersions.useToSign` on the KMS signing key version.
  - `cloudkms.cryptoKeyVersions.viewPublicKey` on the KMS signing key version, when issuing a certificate.

Session keys:

- Create session key pair:
  - `cloudkms.cryptoKeyVersions.useToEncrypt` on the KMS encryption key.
  - `datastore.entities.create` on the `session_keys` kind, under the namespace specified by you.
- Retrieve session key pair:
  - `datastore.entities.get` on the `session_keys` kind, under the namespace specified by you.
  - `cloudkms.cryptoKeyVersions.useToDecrypt` on the KMS encryption key.
- Encrypt or decrypt with key pair: No additional permissions needed once key pair is in memory.

## Limitations

- All the GCP resources must be located in the same GCP project and region.
