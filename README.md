# Awala key stores for Node.js-powered, cloud-agnostic nodes

`@relaycorp/awala-keystore-cloud` is a Node.js library that implements [Awala](https://awala.network/) keystores across a range of cloud providers and open source backing services, so that server-side apps can be deployed to a wide variety of platforms.

This documentation is aimed at developers integrating the library and/or seeking to contribute to the project. If you're the operator of an app powered by this library, please refer to the docs on [docs.relaycorp.tech](https://docs.relaycorp.tech/awala-keystore-cloud-js/).

## Integration

The library is available on NPM as [`@relaycorp/awala-keystore-cloud`](https://www.npmjs.com/package/@relaycorp/awala-keystore-cloud), and you can install it as follows:

```
npm i @relaycorp/awala-keystore-cloud
```

## Development

The unit test suite can be run the standard way on Node.js: `npm test`.

### Integration test suite

The integration tests aren't currently run on CI, and can be run with `npm run test:integration:local`. Note that some environments variables must be set, and others are optional:

- [`GOOGLE_APPLICATION_CREDENTIALS`](https://cloud.google.com/docs/authentication/getting-started) (required), using a service account. **Make sure to create a brand new, temporary GCP project**. All GCP resources will be created within the same project where the service account lives. The GCP service account should be allowed to manage KMS and Datastore resources.
- `GCP_LOCATION` (default: `europe-west3`). The location where resources will be created.

The test suite will automatically delete all the resources it created, except for those that can't be deleted (e.g., GPC KMS key rings). Existing resources are not modified.
