# Flatten CNAME

Flatten CNAME is a global Technitium DNS Server post-processor for `A` and `AAAA` responses.

It rewrites the final `ANSWER` section so that aliases inside selected domains are flattened to synthesized address records, while preserving any alias records that appear before the filtered part of the chain.

## How it works

1. The app runs as an `IDnsPostProcessor`, so it sees the DNS response after the server has already built the answer.
2. It walks the `ANSWER` chain starting from the original QNAME.
3. If the current owner name is outside `filterDomains`, the app preserves the alias record and continues.
4. Once the current owner name matches `filterDomains`, the app tries to flatten from that point.
5. Fast path: if the current `ANSWER` already contains the rest of the alias chain and the final `A`/`AAAA`, the app rewrites only that tail section.
6. Fallback path: if the current `ANSWER` is incomplete, the app resolves the filtered alias internally with `DirectQueryAsync()` and synthesizes address records for that owner name.
7. The app skips DNSSEC-aware responses and returns the original response unchanged if flattening fails, loops, times out, or exceeds `maxDepth`.

## Result

With `filterDomains = ["example.com"]`:

- `ab.example.com -> CNAME -> a.example.com -> A 1.1.1.1` becomes `ab.example.com -> A 1.1.1.1`
- `abc.example2.com -> CNAME -> ab.example.com -> CNAME -> a.example.com -> A 1.1.1.1` becomes:
  - `abc.example2.com -> CNAME -> ab.example.com`
  - `ab.example.com -> A 1.1.1.1`

## Notes

- Supports both `CNAME` and `ANAME` aliases in the response chain.
- `bypassDomains`, `bypassNetworks`, and `bypassLocalZones` can exclude specific requests from post-processing.
- `defaultTtl` is used only when the app synthesizes address records and no lower TTL can be derived from the chain.
