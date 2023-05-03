# Awala key stores for Node.js-powered, cloud-agnostic nodes

`@relaycorp/awala-keystore-cloud` is a Node.js library that implements [Awala](https://awala.network/) keystores across a range of cloud providers and open source backing services, so that server-side apps can be deployed to a wide variety of platforms.

This documentation is aimed at developers integrating the library and/or seeking to contribute to the project. If you're the operator of an app powered by this library, please refer to the docs on [docs.relaycorp.tech](https://docs.relaycorp.tech/awala-keystore-cloud-js/).

## Integration

The library is available on NPM as [`@relaycorp/awala-keystore-cloud`](https://www.npmjs.com/package/@relaycorp/awala-keystore-cloud), and you can install it as follows:

```
npm i @relaycorp/awala-keystore-cloud
```

### Initialising the private key store

The configuration of the adapter is done via environment variables, so the actual initialisation of the store is done with a simple function call. For example:

```typescript
import {
  Adapter,
  initPrivateKeystoreFromEnv,
} from '@relaycorp/awala-keystore-cloud';
import type { PrivateKeyStore } from '@relaycorp/relaynet-core';

function initPrivateKeystore(): PrivateKeyStore {
  return initPrivateKeystoreFromEnv(Adapter.GCP);
}
```

The following environment variables must be defined depending on the adapter:

- GCP:
  - `KS_GCP_LOCATION` (for example, `europe-west3`).
  - `KS_KMS_KEYRING`: The KMS keyring holding all the keys to be used.
  - `KS_KMS_ID_KEY`: The name of the KMS key whose versions will back Awala identity keys.
  - `KS_KMS_SESSION_ENC_KEY`: The name of the KMS key used to encrypt Awala session keys.
- Vault:
  - `KS_VAULT_URL`: The URL to Vault.
  - `KS_VAULT_TOKEN`: The user's access token.
  - `KS_VAULT_KV_PREFIX`: The path prefix for the key-value backend.

## Development

The unit test suite can be run the standard way on Node.js: `npm test`.

### Integration test suite

The integration tests aren't currently run on CI, and can be run with `npm run test:integration:local`. Note that some environments variables must be set, and others are optional:

- [`GOOGLE_APPLICATION_CREDENTIALS`](https://cloud.google.com/docs/authentication/getting-started) (required), using a service account. All GCP resources will be created within the same project where the service account lives. The GCP service account should be allowed to manage KMS resources.
- `GCP_LOCATION` (default: `europe-west3`). The location where resources will be created.

The test suite will automatically delete all the resources it created, except for those that can't be deleted (e.g., GPC KMS key rings). Existing resources are not modified. However, this may not always be true due to bugs, so **always create a brand new, temporary GCP project**.

## Design decisions

### GCP keystores

- [Since KMS doesn't support (EC)DH keys](https://github.com/relaycorp/awala-keystore-cloud-js/issues/5), we had to use envelope encryption to secure the session private keys at rest in the database (using a customer-managed KMS encryption key). The alternative was to use Secret Manager, but it was ruled out because:
  - It'd be easier to maintain data relationship integrity with a single DB record for each session key pair, compared to having a DB record and a Secret Manager secret for each key pair. For example, if whilst creating a new key pair the secret were successfully added to Secret Manager but the DB record creation fails, we'd have to implement a rollback mechanism to avoid leaving the two sources out of sync (and even this wouldn't be 100% reliable).
  - As of this writing, Secret Manager has a limit of 90,000 access requests per minute per project.
- We're wrapping all GCP errors with a [VError](https://www.npmjs.com/package/verror) subclass to provide meaningful stack traces and error messages, since GCP libraries produce utterly meaningless errors.
