"""Collector package overview

This folder groups the in-house URL collection logic. Key points:

- `providers/` - implementations that fetch URLs from archive indexes
  or third-party APIs. Providers are split into `archive/` and
  `external/` subpackages to make the intention clear.
- `aggregator.py` - orchestration entrypoint used by the recon pipeline.
- `crawler.py` - lightweight in-house crawler implementation.
- `observability.py`, `metrics.py`, `rate_limiter.py` - support
  utilities for provider instrumentation and rate-limiting.

Why this layout?
- Grouping archive-specific code helps when adding new archive
  providers (Wayback, CommonCrawl) without cluttering the root of
  `providers/`.
- Keeping `providers.__init__` re-exporting the common names preserves
  backwards compatibility for imports like
  `from src.recon.collectors.providers import wayback`.

If you'd like, I can also:
- Move `aggregator_stream.py` into an `aggregators/` folder.
- Add small README files under each subpackage describing configuration.
