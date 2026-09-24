# Changelog

## v3.0.1 — unreleased

Patch release that fixes a breaking regression in v3.0.0. **Upgrade from v2.x
straight to v3.0.1; do not use v3.0.0.**

### Fixed

- **Upgrading a v2.x stack to v3.0.0 fails and rolls back.** v2.x set
  `BucketNamespace: account-regional` on every bucket (the `-an` bucket-name
  suffix depends on it). #51 removed that override along with
  `CloudFrontLogsBucket`, so it shipped in v3.0.0. `BucketNamespace` can only
  change by replacing the bucket, and CloudFormation can't replace a bucket
  with a fixed name, so every upgraded stack fails with:

  ```
  UPDATE_FAILED AWS::S3::Bucket S3AccessLogsBucket
  CloudFormation cannot update a stack when a custom-named resource requires
  replacing. Rename <slug>-s3-logs-<account>-<region>-an and update the stack again.
  ```

  The override is back on `S3AccessLogsBucket` and `SiteBucket`. Both buckets
  now synthesize with exactly the properties a v2.4.0 stack deployed, so
  neither bucket is updated or replaced.

### Added

- `bucket_namespace: str | None = "account-regional"` controls the namespace.
  The default fits every stack created on v2.x. Pass `None` **only** if the
  stack was first created on v3.0.0, so its buckets never had a namespace.
  Otherwise v3.0.1 hits the same replacement failure in reverse. Any other
  value raises at synth.

### Upgrade notes (v2.x → v3.x)

- **`CloudFrontLogsBucket` was removed in v3.0.0.** It had
  `RemovalPolicy.RETAIN`, so the upgrade removes it from the stack but leaves
  the bucket (`<slug>-cf-logs-<account>-<region>-an`) orphaned in your
  account. Nothing writes to it any more. Once you no longer need its logs,
  empty and delete it by hand.
- The other v3 breaking changes are unchanged; see README
  "Breaking changes in v3".

## v3.0.0

See README "Breaking changes in v3". Known regression: fails to upgrade v2.x
stacks (fixed in v3.0.1).
