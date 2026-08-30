# ajlangweb — a Flask-like web framework for AJOS

Write web apps in AJLang, served by the guest's own HTTP server on port 80
(host preview: http://127.0.0.1:9080/).

## Quick start

1. Create `webapp/mypage.aj` in the repo:

```
import "web"

call web_header("My page")
print "<p>Hello " + web_esc(web_form("name")) + "</p>"
print "<p>Path: " + web_path() + ", method: " + web_method() + "</p>"
call web_footer()
```

2. `make` (bakes `webapp/*` into the image) and run the guest.
3. Open http://127.0.0.1:9080/app/mypage

## Routing

Every request to `/app/<name>` runs `webapp/<name>.aj` through the interpreter
(GET and POST). Branch on `web_method()` and `web_path()` inside the script —
that is your router. Redirect with `web_redirect("/app/other")` (sends 302).

## Request builtins (native, in-kernel)

| Builtin | Returns |
|---|---|
| `web_method()` | `"GET"` or `"POST"` |
| `web_path()` | request path without query, e.g. `/app/index` |
| `web_query(name)` | decoded query param |
| `web_form(name)` | decoded POST form field (URL-decoded, `+` = space) |
| `web_redirect(loc)` | flag a 302 to `loc`; script output is discarded |
| `num(s)` | parse integer (for counters read from the db package) |

## Framework package: `import "web"`

- `web_header(title)` / `web_footer()` — dark-themed page chrome
- `web_esc(s)` — HTML-escape `& < >` (ALWAYS escape user input; XSS-safe)
- `web_route(p)` — true when the request path is `p`

## Persistence: `import "db"`

`db_set(name, key, value)` / `db_get(name, key)` — key/value store in
`<name>.db`. **Use a `/mnt/...` name** (e.g. `/mnt/gb` → `/mnt/gb.db` on the
IDE disk): fast, persistent across reboots, and avoids the boot-floppy write
latency (~50 s per write) and root-dir visibility quirks.

## Constraints (AJLang)

- Strings cap at 255 bytes — print output incrementally; cap form fields
  (the guestbook truncates messages at 110).
- One global variable table — prefix package internals (`web_`, `db__`).
- Every assignment needs `let`, even re-assignment.
- Files under `/mnt/` require the VFS file builtins (in-kernel interpreter).

## Demo

`webapp/index.aj` — a guestbook: POST form → `db_set` → entries rendered
newest-first, XSS-escaped, persistent across reboots.
