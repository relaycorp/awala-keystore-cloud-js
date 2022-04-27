# GCP- and Node.js-powered Awala Key Stores

This library implements the following Awala key stores:

- `PublicKeyStore` and `CertificateStore` using [Firestore](https://cloud.google.com/firestore).
- `PrivateKeyStore` using [Secret Manager](https://cloud.google.com/secret-manager/). We'll replace Secret Manager with [KMS](https://cloud.google.com/security-key-management) once/if [PKI.js adds support for HSMs/KMSs](https://github.com/PeculiarVentures/PKI.js/issues/344).
