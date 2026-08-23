# AJLang — A Programming Language for AJOS

**File extension:** `.aj`

AJLang is implemented and ready to use. Run it on your Mac:

```bash
python run_aj.py examples/hello.aj
python -m ajlang examples/fib.aj
```

## Language Reference

See `ajlang/README.md` for full syntax. Highlights:

- `print expr` – output
- `input x` or `input x "prompt"` – read from stdin
- `let x = expr` – variables
- `def name(a, b) ... end` – functions with `return`
- `if/else/end` – conditionals
- `while/do/end` – loops
- `for i = 1 to 10 do ... end` – for loops
- `+ - * / %`, `== != < >`, `and or not` – operators

## Examples

- `examples/hello.aj` – basic print and variables
- `examples/fib.aj` – Fibonacci loop
- `examples/conditions.aj` – if/else and booleans
- `examples/functions.aj` – user-defined functions, recursion
- `examples/for_loop.aj` – for loop and modulo
- `examples/input_demo.aj` – read user input
- `examples/packages_demo.aj` – `import`, the `http`/`db` packages

## Packages: `import` and `/opt/`

AJOS ships a native, in-kernel copy of AJLang (`src/ajlang.c`) that runs
`.aj` scripts via the `ajlang <file>` shell command — separate from the
Python reference implementation above. It supports one more thing the
reference doesn't: `import`.

```
import "http"
import "db"

let page = http_fetch("http://example.com/")
print page
```

`import "name"` (own line, string literal, nothing else on the line) pulls
in `/opt/name.aj` and splices its source before your script, so any `def`
it declares becomes callable as if you'd written it yourself. It has to be
the literal file `/opt/name.aj` — there's no search path or version
resolution. Only your top-level script can `import`; a package under
`/opt/` can't import another package (v1 limitation, keeps the splice a
simple one-pass operation with no cycle detection needed).

Packages that ship with AJOS, all under `/opt/`:

- **`http`** – `http_fetch(url)`, `http_fetch_save(url, path)`
- **`db`** – `db_set(name, key, value)`, `db_get(name, key)`,
  `db_list(name)`: a flat-file key/value store, `name.db` in the current
  directory, one `key=value` line per entry
- **`editor`** – `edit_file(path)`

Install your own package with `install <file> <name>`, which copies it to
`/opt/<name>.aj` (same as `cp <file> /opt/<name>.aj`) so `import "<name>"`
picks it up.

## Native builtins (in-kernel interpreter only)

These call straight into AJOS itself; the packages above are just thin
AJLang wrappers around them.

| Builtin | Behavior |
|---|---|
| `dns(hostname)` | Resolves a hostname, returns its IPv4 as a dotted string, or `""` on failure/timeout. |
| `file_read(path)` | Returns a file's contents as a string. |
| `file_write(path, content)` | Writes a string to a file. Returns `1`/`0`. |
| `http_get(url)` | Plain HTTP GET (`http://host[:port]/path`, no HTTPS). Returns the response body. |
| `http_get_save(url, path)` | Same fetch, but writes the full response body straight to a file. Returns `1`/`0`. |
| `str_len(s)` | Length of `s`. |
| `str_find(haystack, needle)` | Index of the first occurrence of `needle`, or `-1`. |
| `str_sub(s, start, len)` | Substring from `start`, `len` chars (negative `len` means "to the end"). |
| `edit(path)` | Opens `path` in the AJOS editor. |

**String size limit**: every AJLang string — a literal, a variable, a
return value — is capped at 255 bytes. `file_read`, `http_get`, and any
expression built from them silently *truncate* rather than error past
that limit. For a full page or a large file, use `http_get_save` /
`file_write`'s file-based path instead of holding the whole thing in a
string.

**No true local scope**: every variable (including function parameters and
anything declared with `let` inside an `if`/`while`/`for`) lives in one
global table shared by your script and everything it imports. Reusing a
name across functions is fine as long as calls don't overlap; the
convention in the packages above is a short prefix (`db__foo`) to keep
their internal variables from colliding with a caller's. Also note that
even *reassigning* a variable — inside an `if`, a `while`, anywhere — must
go through `let`; there's no bare `x = y` statement.
