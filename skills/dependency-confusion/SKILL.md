name: dependency-confusion
description: Dependency confusion / supply-chain attack — when a private/internal package name can be squatted on a public registry with a higher version, so a build/install pulls YOUR package and runs its install script. Covers name discovery, version-resolution abuse, and per-ecosystem manifest pitfalls (npm/pip/gem/Maven/Composer). Use on targets with package manifests or CI build configs.
---

# Dependency Confusion (Supply Chain)

Authorized CTF/assessment use. If a build resolves an "internal" package name from a public registry and runs its install hook, you get code execution on the build machine / CI — often where the flag lives. The goal: publish a same-named, higher-version package with a malicious install script.

## 1. Core mechanism

1. The org uses a **private/internal package name** (e.g. `acme-billing-sdk`, `@org/internal-utils`) published only on an internal registry.
2. You **squat the same name** on a public registry (npmjs/PyPI/RubyGems) at a higher version (`9.9.9`).
3. The resolver prefers the **highest matching version** across all configured indexes → your public package wins.
4. Package managers run **lifecycle scripts** (`npm postinstall`, `pip` setup.py/entry points, gem extensions) → your code runs.

## 2. Find the squattable names

- Read the manifest files: `package.json`, `requirements.txt`, `Pipfile`, `pyproject.toml`, `Gemfile`, `pom.xml`, `composer.json`.
- Look for names that are **short/unscoped**, org-specific tokens, or product codenames — and NOT locked to a private registry (`.npmrc` with `@scope:registry=`, `pip` `--extra-index-url` order, Maven `<mirror>`/repo order).
- Check lockfiles: missing/stale lockfiles mean `install` can drift to public metadata.

## 3. Exploit per ecosystem

| Ecosystem | Manifest | Confusion angle |
|---|---|---|
| npm | `package.json` | unscoped private-style names; per-scope registry misconfig; `postinstall` script |
| pip | `requirements.txt`/`pyproject` | `--extra-index-url` merges indexes; `setup.py`/entry points run on install |
| RubyGems | `Gemfile` | gem name squat; native extension build runs code |
| Maven | `pom.xml` | repo order; `maven-compiler`/plugin resolution |
| Composer | `composer.json` | Packagist package name squat |

## 4. Non-destructive PoC (prove it, then weaponize)

1. Publish a package with a benign **callback** (DNS/HTTP to your listener) in the install hook — confirm the target's build pulled it.
2. Once confirmed, re-publish with the real payload (read env/flag, exfil to listener).
3. Trigger the target's `install`/`build` (or wait for CI to run it).

## Cross-cutting
- **It's a version-resolution race, not a direct vuln** — the private package must have a lower version than your squatted one, and the registry must not be locked.
- **The callback PoC is the verification** — never burn the payload before proving the resolution path.
- Self-verify: your listener receives the callback from the build host (not a random resolver).
