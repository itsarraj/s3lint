# s3lint

Audits an S3-compatible bucket's real policy for public-read/
public-write misconfigurations — the exact class of mistake behind
nearly every "open S3 bucket" data-leak headline. Complements this
workspace's `s3sync` (which moves files) with the security-review side
of the same infrastructure.

## Usage

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
s3lint --bucket my-backups                                    # real AWS S3
s3lint --bucket my-backups --endpoint http://localhost:9000   # self-hosted (RustFS/MinIO)
```

Exit code `1` if any public-access statement is found.

## What's checked

Fetches the bucket's real policy document (`GetBucketPolicy`) and
inspects every statement: `Effect: Allow` combined with a wildcard
`Principal` (`"*"` or `{"AWS": "*"}`, including a wildcard buried inside
a principal ARN array) and **no** `Condition` clause is public access.
A `Condition` (e.g. restricting by source IP) means the wildcard isn't
truly unconditional, so it's not flagged. Severity is **CRITICAL** for
write/admin actions (`PutObject`, `DeleteObject`, `DeleteBucket`,
`PutBucketPolicy`, `PutBucketAcl`, or a bare `s3:*` wildcard) and
**WARNING** for read-only public access — a public read-only bucket is
sometimes genuinely intentional (public website assets), public write
essentially never is.

A bucket with **no** policy at all is reported informationally as a
success, not a finding — many buckets correctly rely on IAM alone and
never need a bucket policy.

## Status: built and verified against a real S3-compatible endpoint — including a real bug in how "no policy" was detected

- **10 unit tests** (`cargo test --lib`): public read (bare string
  wildcard principal), public write reported as Critical, a bare `s3:*`
  wildcard action reported as Critical even without a named write
  action, a specific (non-wildcard) principal never flagged, `Deny`
  statements never flagged, a `Condition` clause suppressing an
  otherwise-wildcard principal, an array of actions flagged if *any* one
  of them is a write action, a wildcard buried inside a principal ARN
  array, an empty statement list, and malformed JSON failing cleanly.
- **A real bug caught live**: the "no bucket policy set" case (a
  legitimate, common, non-error state) was meant to be detected by
  checking the AWS SDK error for a `NoSuchBucketPolicy` code — but the
  first version checked `error.to_string()`, which on this SDK only ever
  renders the generic text `"service error"` with no code in it at all.
  Running against a real freshly-created bucket with no policy set
  proved this: the intended graceful path never triggered, and the tool
  hard-failed instead. Fixed by reaching one level deeper into the SDK's
  own structured error (`.as_service_error()` → `.meta().code()`),
  which is where the real `NoSuchBucketPolicy` code actually lives.
- **Live-verified against a real RustFS instance (this workspace's own
  S3-compatible endpoint, confirmed to support the real AWS
  bucket-policy API, not just object storage)** through three real
  states on a real bucket: no policy set (correctly reported as clean,
  after the fix above), a real public read+write policy applied via
  `aws s3api put-bucket-policy` (correctly flagged **CRITICAL**, citing
  the exact actions), and a real `Deny`-with-`Condition` policy
  (correctly reported clean, confirming the tool doesn't just flag every
  wildcard principal on sight).

**Not done / deliberately deferred**: bucket ACL grants
(`AllUsers`/`AuthenticatedUsers` group URIs) aren't checked, only the
JSON bucket policy — RustFS's own ACL model in this sandbox only ever
returned the owner's `FULL_CONTROL` grant with no public-grant support
to test against, so that path is unverified rather than falsely claimed
working. Cross-account (non-wildcard, but still untrusted) principals
aren't flagged — only literal wildcards.
