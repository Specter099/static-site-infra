# Changelog

## v3.1.0 — unreleased

Adds an opt-out for the monitoring resources and ships the v3.0.1 fix below
(v3.0.1 was never tagged; **use v3.1.0 or later, never v3.0.0**). Backwards
compatible: the new parameter defaults to the existing behaviour.

### Added

- `enable_monitoring: bool = True` on `StaticSiteStack`. Pass `False` to skip
  the CloudWatch dashboard, the 4xx/5xx alarms, the alarm SNS topic (and its
  topic policy) and the `AlarmTopicArn` output, e.g. to avoid their standing
  CloudWatch cost. Combining `enable_monitoring=False` with `alarm_topic_arn`
  or `alarm_email` raises `ValueError`; `dashboard_name` is ignored.

### Upgrade notes (v3.0.x → v3.1.0)

- **Default behaviour is unchanged** (`enable_monitoring=True`): no resource
  is added, removed or replaced for existing stacks.
- **Passing `enable_monitoring=False` to an existing stack deletes** the
  dashboard, both alarms and the alarm topic (if the library created it) on
  the next deploy. If you already deleted them by hand, CloudFormation is
  asked to delete resources that no longer exist; run `cdk diff` first and
  watch the first deploy.
- Everything under "v3.0.1" below is included in this release.

## v3.0.1 — folded into v3.1.0 (never tagged)

Patch fix for a breaking regression in v3.0.0, released as part of v3.1.0.
**Upgrade from v2.x straight to v3.1.0; do not use v3.0.0.**

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
stacks (fixed in v3.1.0).
