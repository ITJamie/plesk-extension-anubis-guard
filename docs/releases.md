# GitHub checks and releases

The project is hosted at https://github.com/ITJamie/plesk-extension-anubis-guard.

## Continuous integration

The **CI** workflow runs on branch pushes, pull requests, and manual dispatch. It tests Python 3.9 and 3.13 on Ubuntu 24.04, PHP syntax and SDK boundary behavior, Node 24 frontend behavior, generated nginx syntax, and native MMDB validation. It installs nginx, the MMDB utility, PHP CLI/XML, and test service accounts; it does not install Plesk or run production services. Successful checks build the standard installer and source ZIPs with SHA-256 files, available as the `extension-packages` workflow artifact for 14 days.

`tools/check.sh` uses the host's Plesk PHP and Node by default. Elsewhere, run:

```sh
PHP_BIN=php NODE_BIN=node sh tools/check.sh
```

Portable metadata checks always run. On a Plesk host, the same command also validates against its installed `meta.xsd`. To use another schema copy, set `PLESK_META_XSD=/path/to/meta.xsd`; a missing explicitly configured schema fails the check. GitHub runners do not contain the proprietary Plesk schema, so CI explicitly reports that full schema validation remains a Plesk-host check. Systemd, Plesk integration, and real visitor challenges still require the staging acceptance checks.

## Publish a release

1. Set the new extension version in `src/meta.xml`. ZIP filenames use this value automatically. Update the panel asset versions in `src/plib/controllers/IndexController.php` when assets change, and update README example filenames as appropriate. The separate `runtime.lock.json` controls Anubis's default runtime, not the extension version.
2. Add a nonempty `## VERSION — description` section to `CHANGELOG.md`. Complete local/Plesk staging checks, commit the changes, and push them. Wait for CI to pass.
3. Push an annotated tag matching the metadata exactly. For example, if `src/meta.xml` contains `0.8.2`:

```sh
git tag -a v0.8.2 -m "Anubis Guard 0.8.2"
git push origin v0.8.2
```

The **Release** workflow reruns CI on the tagged commit. Only after all checks and package builds pass does it validate the tag and changelog, rebuild the two packages, verify checksums, and create a published GitHub release. Release notes come from that version's changelog section. Attached files are:

- `anubis-guard-VERSION.zip` — installable Plesk extension; downloads and verifies the pinned Anubis release during installation.
- `anubis-guard-VERSION.zip.sha256`.
- `anubis-guard-VERSION-source.zip` — source archive, not an installer.
- `anubis-guard-VERSION-source.zip.sha256`.

The workflow does not create an offline runtime bundle. That remains available through `tools/build.py --download-runtime` when needed.

No personal access token or repository secret is required: publishing uses GitHub's built-in job token with `contents: write` only in the publishing job. Test jobs use read-only repository access, and checkouts do not retain Git credentials. Repository/organization Actions policy must permit the official actions and the publishing permission. Publishing is restricted to `ITJamie/plesk-extension-anubis-guard`; forks can run CI without publishing a release through this workflow.

A failed check or mismatched tag prevents publication. Fix failures before retrying. Existing releases are never overwritten; rerunning a successfully published tag fails at release creation rather than replacing assets. Use a new version/tag for changes to a published release.

For a local preview of the exact release assets and notes, without publishing:

```sh
python3 tools/release.py --tag v0.8.2
```

Commit and push the workflow files before creating the first release tag. No release is created merely by pushing a branch or opening a pull request.
