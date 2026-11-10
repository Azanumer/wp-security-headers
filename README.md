# WP Security Headers

Sends hardened HTTP security headers — HSTS, CSP, X-Frame-Options, Referrer-Policy and Permissions-Policy — from one Settings page. No `.htaccess` edits, no server config, no Nginx snippet to maintain.

## Headers sent

| Header | Default | Notes |
|---|---|---|
| `Strict-Transport-Security` | On, max-age 1 year, includeSubDomains | Only sent over HTTPS. |
| `X-Content-Type-Options` | `nosniff` | Stops browsers MIME-sniffing responses. |
| `X-Frame-Options` | `SAMEORIGIN` | Or `DENY`, or off (use CSP `frame-ancestors` instead). |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Pick from the full allow-list or turn off. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Free-form; empty disables it. |
| `Content-Security-Policy` | Off by default | Report-only when first enabled. |

## CSP, done safely

CSP is **off by default** and **report-only** when first enabled — a bad policy can break a site, so it should be proven in the browser console before it is enforced. Untick *Report-only* only after the violations stop.

Write `{nonce}` in the policy wherever a per-request nonce belongs:

```
script-src 'self' {nonce}
```

Then output the nonce in your theme:

```php
<script <?php echo wsh_nonce_attr(); ?>>…</script>
```

The nonce is generated once per request (`wsh_csp_nonce()`, filterable via `wsh_csp_nonce`) and substituted into the header automatically. An optional `report-uri` appends violation reporting.

## Installation

1. Upload the plugin folder to `/wp-content/plugins/`.
2. Activate it from **Plugins**.
3. Go to **Settings → Security Headers** and tune the policy.

## Notes

- HSTS `preload` is opt-in — only tick it if the domain is submitted to hstspreload.org, because it is very hard to undo.
- Headers are sent on every response, including wp-admin. If another plugin or your server already sends the same header, browsers use the first one they see — check with `curl -I` and turn off the duplicate here.
- Uninstalling deletes the single `wsh_settings` option.

## License

MIT — see [LICENSE](LICENSE).
