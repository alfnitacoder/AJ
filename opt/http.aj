// http.aj - AJLang package wrapping the native HTTP builtins.
// Install:  install opt/http.aj http        (already baked into /opt/http.aj)
// Use:      import "http"

// Fetch a URL (http:// only, v1) and return the response body as a string.
// Like every AJLang string this is capped at 255 bytes -- fine for small
// API responses, but a real page will come back truncated. Use
// http_fetch_save for anything bigger.
def http_fetch(url)
  return http_get(url)
end

// Fetch a URL and write the full, untruncated response body to a local
// file. Returns 1 on success, 0 on failure.
def http_fetch_save(url, path)
  return http_get_save(url, path)
end
