---
title: "Docker Image Forensics - Layers, History and Secrets in the Filesystem"
category: cloud
subcategory: docker
type: technique
tags: [cloud, docker, image, forensics, layers, history, dive, docker-save, secrets, oci, manifest, whiteout, gitleaks, trufflehog, tar, build-args, dockerfile]
difficulty: easy
summary: "A Docker image is a stack of tar layers plus metadata; secrets deleted in a later layer still exist in the earlier one, and history reveals build args."
when_to_use:
  - "The challenge hands you a .tar image, a registry reference, or a Dockerfile"
  - "You suspect a credential was added then removed during the build"
  - "You need to recover source or config baked into an image"
  - "You want to read the build history / entrypoint / env of an image"
tools: [docker, dive, skopeo, jq, tar, gitleaks, trufflehog]
related: [container-escape, object-storage-misconfig, cicd-attacks, cloud-enum-script]
---

## TL;DR

A Docker/OCI image is an ordered set of filesystem layers (each a tar) plus a JSON config with the
build history, environment and entrypoint. Layers are additive: a file `COPY`d in one layer and
`rm`d in a later one is still fully present in the earlier layer's tar. Extract the layers and
search them, and read the config for env vars and the command history.

## Recognise it

- A `.tar` produced by `docker save`, or an OCI layout directory.
- A registry reference (`registry.example/app:tag`) you can pull.
- A Dockerfile with `COPY . .`, `ARG`/`--build-arg`, or a `RUN` that fetches and deletes a secret.
- The objective is a secret, a private key, source code, or config inside the image.

## Theory

### Image structure

- **`docker save image > image.tar`** produces a tar containing: a `manifest.json`, a per-image
  config JSON (with `history`, `config.Env`, `config.Entrypoint`, `config.Cmd`), and one directory
  (or blob) per layer, each itself a gzipped tar of that layer's filesystem changes.
- **OCI layout / registry**: `index.json` -> manifest (by digest) -> config + layer blobs, all
  content-addressed under `blobs/sha256/`.
- Each layer records the *diff* from the previous one: files added, changed, or deleted. A deletion
  is recorded as a **whiteout** file (`.wh.<name>`) in the later layer - the underlying file still
  exists in the earlier layer's tar.

### Why "deleted" secrets persist

```dockerfile
COPY id_rsa /root/.ssh/id_rsa      # layer N: the key is now in the image
RUN ./deploy.sh && rm /root/.ssh/id_rsa   # layer N+1: adds a whiteout for id_rsa
```

The final container filesystem does not show `id_rsa`, but layer N's tar contains it verbatim.
`docker history` shows the commands; extracting layer N recovers the file. Multi-stage builds and
`--squash` mitigate this, but many images are built without them.

### The config JSON

- `config.Env` - environment variables baked into the image (frequent secret location).
- `history` - every build instruction (with `RUN` commands, unless `--build-arg` secrets were passed
  and BuildKit redacted them). `docker history --no-trunc` prints the full commands.
- `config.Entrypoint` / `config.Cmd` - how the container starts, which reveals the app's real path.
- Labels, exposed ports, working directory.

### Build args are not secrets

`ARG` values passed with `--build-arg` are visible in `docker history` and often in the layer
metadata. Passing a token as a build arg leaks it into the image. BuildKit's `--secret` mount is the
correct mechanism; its absence is a smell.

## Procedure

### With Docker available

```bash
IMG=app:latest

# the build history -- reveals RUN commands, ADD/COPY, build args
docker history --no-trunc "$IMG"

# environment, entrypoint, and all config in one place
docker inspect "$IMG" | jq '.[0].Config | {Env, Entrypoint, Cmd, WorkingDir, Labels}'

# save and unpack to inspect layers directly
docker save "$IMG" -o image.tar
mkdir -p unpacked && tar -xf image.tar -C unpacked
ls unpacked                                   # manifest.json, config, layer dirs/blobs
cat unpacked/manifest.json | jq .

# extract every layer into one tree, in order (later layers overwrite earlier)
mkdir -p rootfs
for layer in $(jq -r '.[0].Layers[]' unpacked/manifest.json); do
  tar -xf "unpacked/$layer" -C rootfs 2>/dev/null || true
done

# search the reconstructed filesystem for secrets
grep -rIE '(AKIA|ASIA|AIza|sk_live_|ghp_|-----BEGIN|password|secret|token)' rootfs/ 2>/dev/null | head
find rootfs -name '*.env' -o -name 'id_rsa' -o -name '*.pem' -o -name '.git' 2>/dev/null
```

### Without Docker (skopeo / manual)

```bash
# pull an image to an OCI/dir layout without a docker daemon
skopeo copy docker://registry.example/app:tag dir:./app
ls app/                                        # manifest, config, blobs by digest
# each blob is a gzipped tar layer; extract them the same way
```

### Layer-by-layer with dive

```bash
# interactive: see which layer added which file, and each layer's wasted space
dive "$IMG"
# dive highlights files that appear in one layer and are removed later
```

## Code - a read-only image tar analyser

```python
#!/usr/bin/env python3
"""Analyse a `docker save` tarball read-only: build history, env vars, and files
that were added in one layer and deleted (whiteout) in a later one.

Also greps every layer for secret-shaped strings. Nothing is executed and nothing
is written outside an optional extraction directory.

Python 3.11+, standard library only. Usage:
    python3 image_analysis.py image.tar
    python3 image_analysis.py image.tar --grep
    python3 image_analysis.py --self-test
"""
from __future__ import annotations

import json
import re
import sys
import tarfile

SECRET_PATTERNS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"ASIA[0-9A-Z]{16}"), "AWS temporary key id"),
    (re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(rb"ghp_[0-9A-Za-z]{36}"), "GitHub PAT"),
    (re.compile(rb"sk_live_[0-9A-Za-z]{24,}"), "Stripe live key"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"eyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\."), "JWT"),
]

INTERESTING_NAMES = re.compile(
    r"(\.env$|(^|/)id_rsa$|\.pem$|\.pfx$|\.p12$|(^|/)\.git/|credentials$|"
    r"\.npmrc$|\.dockercfg$|config\.json$|\.aws/|\.kube/config$)"
)


def load_manifest_and_config(tar: tarfile.TarFile) -> tuple[dict, dict]:
    names = tar.getnames()
    manifest = {}
    if "manifest.json" in names:
        manifest = json.loads(tar.extractfile("manifest.json").read())[0]
    config = {}
    cfg_name = manifest.get("Config")
    if cfg_name and cfg_name in names:
        config = json.loads(tar.extractfile(cfg_name).read())
    return manifest, config


def report_config(config: dict) -> None:
    cfg = config.get("config", {}) or config.get("Config", {})
    print("=== config ===")
    for env in cfg.get("Env", []) or []:
        key = env.split("=", 1)[0]
        flag = "  [!]" if re.search(r"(secret|token|key|passw|cred|api)", key, re.I) else "     "
        print(f"{flag} ENV {env}")
    if cfg.get("Entrypoint"):
        print(f"     ENTRYPOINT {cfg['Entrypoint']}")
    if cfg.get("Cmd"):
        print(f"     CMD {cfg['Cmd']}")
    print("\n=== history ===")
    for h in config.get("history", []):
        line = h.get("created_by", "").strip()
        if line:
            flag = "  [!]" if re.search(r"(secret|token|password|--build-arg|ARG )", line, re.I) else "     "
            print(f"{flag} {line[:160]}")


def scan_layers(tar: tarfile.TarFile, manifest: dict, do_grep: bool) -> None:
    layers = manifest.get("Layers", [])
    print(f"\n=== {len(layers)} layer(s) ===")
    added: dict[str, int] = {}        # filename -> first layer index it appears in
    deleted: dict[str, int] = {}      # filename -> layer index of the whiteout
    findings: list[str] = []

    for idx, layer_name in enumerate(layers):
        member = tar.extractfile(layer_name)
        if member is None:
            continue
        try:
            layer_tar = tarfile.open(fileobj=member, mode="r:*")
        except tarfile.TarError:
            continue
        for m in layer_tar.getmembers():
            base = m.name.rsplit("/", 1)[-1]
            if base.startswith(".wh."):
                real = m.name.replace(".wh.", "")
                deleted[real] = idx
                continue
            if m.name not in added:
                added[m.name] = idx
            if INTERESTING_NAMES.search(m.name):
                findings.append(f"layer {idx}: interesting file {m.name}")
            if do_grep and m.isfile() and m.size < 2_000_000:
                data = layer_tar.extractfile(m)
                if data is None:
                    continue
                blob = data.read()
                for pat, label in SECRET_PATTERNS:
                    if pat.search(blob):
                        findings.append(f"layer {idx}: {label} in {m.name}")
        layer_tar.close()

    print("\n=== files added-then-deleted (still recoverable from the earlier layer) ===")
    ghosts = 0
    for path, del_idx in deleted.items():
        add_idx = added.get(path)
        if add_idx is not None and add_idx < del_idx:
            print(f"  [!] {path}: added in layer {add_idx}, removed in layer {del_idx}")
            ghosts += 1
    if not ghosts:
        print("  none detected")

    if findings:
        print("\n=== findings ===")
        for f in sorted(set(findings)):
            print(f"  {f}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    do_grep = "--grep" in sys.argv
    with tarfile.open(path, "r:*") as tar:
        manifest, config = load_manifest_and_config(tar)
        if config:
            report_config(config)
        if manifest:
            scan_layers(tar, manifest, do_grep)
        else:
            print("no manifest.json found; is this a `docker save` tar?")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        # verify the pure regexes without needing an image
        assert any(p.search(b"AKIAIOSFODNN7EXAMPLE") for p, _ in SECRET_PATTERNS)
        assert any(p.search(b"-----BEGIN OPENSSH PRIVATE KEY-----") for p, _ in SECRET_PATTERNS)
        assert INTERESTING_NAMES.search("app/.env")
        assert INTERESTING_NAMES.search("root/.ssh/id_rsa")
        assert not INTERESTING_NAMES.search("app/main.py")
        print("[+] self-test ok")
        sys.exit(0)
    sys.exit(main())
```

## Variants & pitfalls

- **Whiteouts do not delete the data.** A `.wh.id_rsa` in layer N+1 hides `id_rsa`, but layer N's
  tar still contains it. This is the single most productive image-forensics idea.
- **`docker history` truncates**; use `--no-trunc`. Build args and inline `RUN` secrets show here.
- **BuildKit `--secret` mounts** are the correct way to use a secret at build time without baking it
  in; their absence (a `COPY`d or `ARG`d credential) is the finding.
- **Multi-stage builds** can drop secrets by only copying artifacts to the final stage - but the
  builder stage's layers may still be present in an unsquashed image or intermediate cache.
- **OCI vs Docker manifest**: newer `docker save` and `skopeo` produce OCI layouts where layers are
  content-addressed blobs under `blobs/sha256/`; the reconstruction logic is the same.
- **Compressed layers**: layer tars are usually gzipped; `tarfile` with `r:*` auto-detects.
- **`config.Env` secrets** are the fastest win and need no extraction - read the config JSON first.
- **`.git` directories** copied by `COPY . .` leak full history and often credentials.

## Hardening checklist

- Never `COPY` or `ARG` secrets into an image; use BuildKit `--secret` mounts or runtime injection.
- Use multi-stage builds and copy only the needed artifacts to the final stage.
- Add a `.dockerignore` to keep `.git`, `.env`, and keys out of the build context.
- Scan images in CI with `trivy`, `grype`, `gitleaks`, or `trufflehog` before pushing.
- Do not store secrets in `ENV`; pull them at runtime from a secrets manager.

## Tools

- `docker history --no-trunc`, `docker inspect`, `docker save`.
- `dive` - interactive layer explorer with efficiency/leftover analysis.
- `skopeo` - pull/inspect images without a daemon.
- `gitleaks`, `trufflehog` - secret scanning across layers and history.
- `trivy image`, `grype` - vulnerability and misconfig scanning.

## References

- Docker documentation: "About storage drivers" (layers and whiteouts), "docker history",
  "Build secrets" (BuildKit `--secret`).
- OCI Image Format Specification (manifest, config, layers).
