# Publishing notes

This repository is intended to be safe for public GitHub publication.

Before pushing, verify again that you are NOT including:
- private keys, certificates, seed phrases, wallet dumps, or `.env` files
- production passwords, tokens, API keys, or cloud credentials
- build artifacts, local databases, logs, snapshots, or support bundles
- internal-only IPs, hostnames, or configs that reflect real production infrastructure

Current deploy/config and testnet files in this repo are example or testnet-oriented configs and must not be reused as production secrets.
