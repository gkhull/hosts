# blocklist-builder

Combines the lists in `sources.txt` into one AdGuard / uBlock Origin blocklist, removes whitelisted domains, adds blacklisted domains, and writes `dist/blacklist.txt`. No runtime dependencies.

## Files

| File | Purpose |
|---|---|
| `sources.txt` | One list URL per line |
| `whitelist.txt` | Domains to remove (and their subdomains) |
| `blacklist.txt` | Domains to add as `||domain^` |
| `scripts/build.mjs` | The builder |

Each source is saved to `temp/` (`01.txt`, `02.txt`, ...) with `temp/manifest.txt` mapping them to URLs.

## Local build

```sh
npm run build
# -> dist/blacklist.txt, dist/index.html
```

Requires Node 18.17 or newer.

## Cloudflare Pages setup

1. Push this repo to GitHub.
2. In Cloudflare, go to Workers & Pages, create a Pages project, and connect the repo.
3. Build settings: build command `npm run build`, output directory `dist`.
4. Environment variable: `NODE_VERSION` = `22`.
5. Subscribe in uBlock Origin or AdGuard to `https://<project>.pages.dev/blacklist.txt`.

Pages rebuilds on every push, so edits made on GitHub's website also trigger a rebuild.

### Daily rebuild for upstream changes

1. In the Pages project, go to Settings > Builds > Deploy hooks and create a hook.
2. In the GitHub repo, add a secret named `CF_PAGES_DEPLOY_HOOK` with the hook URL.

`.github/workflows/scheduled-rebuild.yml` then triggers a build every day.

### Keeping the input files elsewhere

Set any of these as Pages environment variables to use a URL instead of the local file:

- `SOURCES_URL`, for example a raw GitHub URL to another `sources.txt`
- `WHITELIST_URL`
- `BLACKLIST_URL`

Optional: `BLOCKLIST_TITLE` sets the title in the header of the output file.

## Matching rules

- **Whitelist:** a whitelisted domain also removes its subdomains. A whitelisted subdomain does not remove a blocked parent domain.
- **Blacklist:** each entry becomes `||domain^`, which also blocks subdomains.
- **Conflicts:** a domain in both files stays blocked, and the build logs a warning.
- **Source allow rules:** `@@||domain^` rules inside source lists are dropped. Use `whitelist.txt` instead.
- **Other rules:** cosmetic rules and rules with `$` modifiers are kept verbatim in the output.
- **Failed sources:** a source that fails to download is logged and skipped. The build still succeeds.
