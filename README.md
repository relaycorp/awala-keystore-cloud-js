# Key Stores for server-side, Node.js-powered, cloud-agnostic, Awala nodes

## Private key stores

- `GCPPrivateKeyStore` is backed by [Firestore](https://cloud.google.com/firestore) in Datastore mode, with the private key field encrypted at rest with GCP [KMS](https://cloud.google.com/kms). We wish we could've just stored the private key in KMS, but [PKI.js doesn't support fully that yet](https://github.com/PeculiarVentures/PKI.js/issues/344).
