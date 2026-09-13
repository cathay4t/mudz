# TODO

- DoH HTTP status handling follow-ups (RFC 8484 section 4.2.1): the
  client retries 429 and 5xx on a fresh pool and honours integer-second
  `Retry-After` values, but these gaps remain:
  - `401` is permanent; if authentication is ever added, retry once
    with the same server after refreshing credentials.
  - `406` and `415` are returned as permanent errors instead of
    actively switching to another DoH server. Group fan-out covers
    this when multiple upstreams are configured, but a single-upstream
    group cannot switch.
  - HTTP-date `Retry-After` values are ignored.
  See `DohAttemptError` in `src/lib/doh.rs`.
