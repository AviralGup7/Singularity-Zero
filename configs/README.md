# Configs Layer

This folder is the canonical location for configuration assets.

Compatibility notes:
- Runtime reads config.example.json from this directory and user-supplied config files.
- New code should prefer config loading through core.config.load_config.
