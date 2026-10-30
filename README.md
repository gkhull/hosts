# blocklist-builder

Combines the lists in `sources.txt` into one AdGuard / uBlock Origin blocklist, removes whitelisted domains, adds blacklisted domains, and writes `dist/blacklist.txt`. No runtime dependencies. Hosted on GitHub Pages at `https://hosts.gkhull.com/blacklist.txt`.

## Files

| File | Purpose |
|---|---|
| `sources.txt` | One list URL per line |
| `whitelist.txt` | Domains to remove (and their subdomains) |
| `blacklist.txt` | Domains to add as `||domain^` |
| `scripts/build.mjs` | The builder |
| `.github/workflows/github-pages.yml` | Builds and deploys to GitHub Pages |

Each source is saved to `temp/` (`01.txt`, `02.txt`, ...) with `temp/manifest.txt` mapping them to URLs.

## Local build

```sh
npm run build
# -> dist/blacklist.txt, dist/index.html
```

Requires Node 18.17 or newer.

## GitHub Pages setup

1. In the repo, go to **Settings > Pages** and set **Source** to **GitHub Actions**.
2. Under **Custom domain**, enter `hosts.gkhull.com` and save. The workflow also writes this into `dist/CNAME`.
3. At your DNS provider, add a CNAME record: name `hosts`, target `<your-github-username>.github.io`.
4. Once the domain check passes, enable **Enforce HTTPS**.
5. Subscribe in uBlock Origin or AdGuard to `https://hosts.gkhull.com/blacklist.txt`.

The workflow runs on every push to `main` and once a day at 05:17 UTC, so upstream list changes reach you. You can also run it from the **Actions** tab with **Run workflow**.

Remove the old Cloudflare Pages project (or its custom domain) so `hosts.gkhull.com` points only at GitHub.

## Matching rules

- **Whitelist:** a whitelisted domain also removes its subdomains. A whitelisted subdomain does not remove a blocked parent domain.
- **Blacklist:** each entry becomes `||domain^`, which also blocks subdomains.
- **Conflicts:** a domain in both files stays blocked, and the build logs a warning.
- **Source allow rules:** `@@||domain^` rules inside source lists are dropped. Use `whitelist.txt` instead.
- **Other rules:** cosmetic rules and rules with `$` modifiers are kept verbatim in the output.
- **Failed sources:** a source that fails to download is logged and skipped. The build still succeeds.
