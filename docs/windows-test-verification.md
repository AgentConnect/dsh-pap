# Windows test verification

Verified on Windows with Node 22.22.3 on 2026-11-09. This is local regression
evidence, not a successful public identity or remote protocol acceptance run.

`npm run test:p22` initially failed because Windows stat mode bits do not
represent POSIX file permissions, and because an absolute drive path passed to
Node `--import` is parsed as a URL with the unsupported `d:` scheme. The HTTPS
fixtures also require OpenSSL on the test process PATH.

The changes keep the encrypted-state round trip and cross-process persisted
cooldown assertions enabled on Windows. Only the POSIX mode assertion is
conditional. The child-process loader uses a file URL on all platforms.
No production transport, authentication, signing or storage implementation is
changed.

Validation: `npm run test:p22`, with Git for Windows OpenSSL added to the
invoking process PATH, passed all 49 tests and both TypeScript checks. This
includes the actual local HTTPS fixture and the fresh-process test that checks
the persisted cooldown before any signer or network invocation.

The production DSH domain connector still rejects loopback/private origins.
Local fixture HTTPS success does not demonstrate authenticated access through
the Windows Desktop plugin, external services, or cross-protocol writes.
