# shopify-app-audit

**One command that tells you whether Shopify is about to delist your app, and whether your running app can be hacked in the ways Shopify has warned about.**

```bash
npx shopify-app-audit                                       # Will Shopify block my app?
npx shopify-app-audit probe --url https://staging.myapp.com # Can my live app be hacked?
```

No signup, no config. It runs on your repo in a few seconds:

```text
shopify-app-audit 0.2.0 · public app · 2026-11-23

✖ 5 blocking issues  4 warnings, 4 to do by hand

Shopify deadlines
  ● 2026-11-20  in effect  IP allowlist
  ○ 2026-12-01  8d         Network access declaration
  ○ 2027-01-01  39d        Expiring offline access tokens

Blocking (5)
✖ Network access declaration NETWORK_ACCESS
    The app runs on the online store (theme app extension (extensions/reviews)) but
    shopify.app.toml has no [network_access] allowed_sources.
    deadline: 2026-12-01 (in 8 days). Deploys (and App Store submissions) are rejected.
    at shopify.app.toml
    fix: Add [network_access] with allowed_sources listing every external HTTPS origin ...

Next
  → Fix the blocking items above, then run this again.
  → Test the running app:  npx shopify-app-audit probe --url https://staging.your-app.com
```

## 1. "Will Shopify block my app?"

It reads your app's code and `shopify.app.toml`, then lists what will break and when. For example:

- "Your app loads scripts on the storefront but doesn't declare which domains it calls. Deploys get rejected from Dec 1."
- "You're on non-expiring tokens. You get delisted Jan 1, and API calls fail from Apr 1."
- "You use ScriptTags. They stop loading Mar 1."

Deadlines that have already passed show as **enforced**, not as countdowns. Every item comes with the exact file and line and how to fix it.

### Already enforced: prove your IP allowlist works

Since November 20, 2026, public apps without an IP allowlist are delisted. It can't be seen in code, so give the tool an Admin API token for a dev store and run it from your laptop or CI, outside your servers' IP ranges:

```bash
SHOPIFY_ADMIN_TOKEN=shpat_... npx shopify-app-audit --shop my-dev-store.myshopify.com --admin-token-env SHOPIFY_ADMIN_TOKEN
```

It sends one `{ shop { id } }` Admin API query. A `403` from Shopify means the allowlist is enforced. If the query succeeds, the token works from anywhere and the check fails. This is the check Shopify's docs recommend. The token is only ever sent to `https://<shop>.myshopify.com`.

## 2. "Can my live app be hacked?"

It sends your app the same fake requests an attacker would, and tells you which ones the app wrongly accepts:

- A fake webhook from Shopify
- A fake storefront (app proxy) request
- A request that claims to be a different store
- Loading your app inside a stranger's site (clickjacking)

## Why not just Shopify's scanner?

Shopify's [`shopify app security check`](https://shopify.dev/docs/api/shopify-cli/app/app-security-check) reads your code. It doesn't track the deadlines or test the running app. This does both, locally or in CI. Run them together.

### Why now

In October 2026, attackers took over several Shopify apps' backends and used them to send shoppers to fake checkouts. Shopify responded with dated requirements, and apps that miss them get delisted, blocked from new installs, or have their API calls rejected ([Securing your app, together](https://shopify.dev/changelog/blog/securing-your-app-together), [About app security](https://shopify.dev/docs/apps/build/security)).

## What it checks, in detail

### Deadlines (static, reads your repo)

| Check | Deadline | What happens if you miss it |
| --- | --- | --- |
| `[network_access]` declared for storefront apps, and every external origin your extensions call is in `allowed_sources` | Dec 1, 2026 | Deploys and App Store submissions rejected |
| Expiring offline access tokens (`expiringOfflineAccessTokens`, `expiring=1`, refresh token stored in your `Session` model) | Dec 1, 2026 (new custom apps), Jan 1, 2027 (public) | Delisted, then Admin API 403s from Apr 1, 2027 |
| `abandonedCheckoutUrl` reads | Dec 1, 2026 | Query fails without level 2 protected customer data |
| ScriptTag API and `write_script_tags` | Mar 1, 2027 | Script tags stop loading |
| Bulk operations | Nov 12, 2026 | Blocked without an IP allowlist |
| End-of-life Admin API versions | Ongoing | Shopify falls forward to the oldest supported version |
| HTTP URLs in `shopify.app.toml`, missing compliance webhooks | App review | Rejected |
| IP allowlist, MFA on partner accounts | Nov 2026 | Listed as manual to-dos, since code can't show them |

It also flags storefront code that runs strings as code or HTML (`eval`, `new Function`, `innerHTML`). That's the pattern behind the October checkout redirects: a config server returned JavaScript and the theme extension ran it.

### Runtime probe (sends requests to a URL you own)

| Probe | Request it sends | Fails when |
| --- | --- | --- |
| Webhook HMAC | `POST` to each webhook route with a wrong `X-Shopify-Hmac-SHA256`, and with none | The app returns 2xx |
| App proxy signature | `GET` the proxy route with no `signature`, and with a wrong one | The app returns 2xx |
| `?shop=` trust | `GET /app?shop=a.myshopify.com` and `?shop=b.myshopify.com` with no session token | The app returns data |
| Clickjacking | `GET /app` | No `frame-ancestors`, or it allows `*` / `https:` |
| Transport | `GET` over `http://` | The app answers instead of redirecting; also warns on missing HSTS |

Webhook routes and the proxy route come from `shopify.app.toml`. Override them with `--webhook-path`, `--proxy-path` and `--app-path`. Payloads are fake and marked as probes, and the tool only sends `GET` and webhook-shaped `POST` requests.

**Only probe apps you own or have written permission to test.** Point it at staging if you can.

## Try it locally

```bash
npm install && npm run build
node dist/cli.js test/fixtures/vulnerable-app
node examples/demo-app-server.mjs &                  # deliberately vulnerable backend on :3456
node dist/cli.js probe --url http://localhost:3456 --webhook-path /webhooks --proxy-path /proxy
```

Run the server with `SECURE=1` to see every probe pass.

To run a branch or commit without npm: `npx github:enclave-ai/shopify-app-audit#main`.

## Options

```
--distribution public|custom     Deadlines differ by distribution (default: public)
--format text|json|markdown|sarif
--output <file>                  Write the report to a file
--badge <file>                   Write a shields.io endpoint badge
--fail-on fail|warn|none         Exit code policy (default: fail)
--today YYYY-MM-DD               Evaluate deadlines as of a date
--client-secret-env <name>       Also send one correctly signed webhook
--shop <domain>                  Your dev store, for --admin-token-env and probe requests
--admin-token-env <name>         Verify the IP allowlist with one Admin API request (expects 403)
```

## GitHub Action

```yaml
- uses: enclave-ai/shopify-app-audit@v0
  with:
    distribution: public
    probe-url: https://staging.your-app.com          # optional
    shop: my-dev-store.myshopify.com                 # optional: verify the IP allowlist
    admin-token: ${{ secrets.SHOPIFY_ADMIN_TOKEN }}  # from GitHub's runners, outside your IP ranges
```

It prints the report in the job log, writes a job summary and a SARIF file for code scanning, and runs the code at the action's ref, so it doesn't need a published npm release. See [examples/github/shopify-app-audit.yml](examples/github/shopify-app-audit.yml).

## Limits

Passing this tool doesn't mean your app is secure. The static checks match patterns, so they miss things and sometimes flag safe code. The probe only tests a few unauthenticated requests. It can't log in as two merchants and test whether one store can read another's data, which is the cross-shop IDOR Shopify ranks among the top risks.

[Enclave](https://enclave.ai) does that: an AI pentester that signs in as real users and tests every route for tenant isolation, auth bypass and injection. You can also [get a free AI vulnerability scan of your app's repo](https://app.enclave.ai/login?utm_source=shopify-app-audit&utm_medium=readme&utm_campaign=shopify-app-audit). Nothing in this tool needs it.

## Contributing

Shopify updates these requirements often. The deadline calendar is in [`src/deadlines.ts`](src/deadlines.ts), with a source link on every entry. PRs welcome.

MIT
