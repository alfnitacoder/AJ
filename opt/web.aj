// web.aj - ajlangweb: a tiny Flask-like web framework for AJOS.
//
// The HTTP server (src/http.c) maps /app/<script> to webapp/<script>.aj,
// injects the request context, and captures `print` output as the response.
// Import this package for layout + escaping helpers:
//
//   import "web"
//   call web_header("My page")
//   print "<p>Hello " + web_esc(web_form("name")) + "</p>"
//   call web_footer()
//
// Request builtins (kernel): web_method(), web_path(), web_query(name),
// web_form(name), web_redirect(location). Strings are capped at 255 bytes
// and every assignment must use `let` (one global table; web_ prefix is
// reserved by this package).

def web_route(p)
  return web_path() == p
end

def web_esc(s)
  // HTML-escape & < > char by char (result capped at 255 bytes)
  let web_e__r = ""
  let web_e__i = 0
  let web_e__n = str_len(s)
  while web_e__i < web_e__n do
    let web_e__c = str_sub(s, web_e__i, 1)
    if web_e__c == "&" then
      let web_e__r = web_e__r + "&amp;"
    else
      if web_e__c == "<" then
        let web_e__r = web_e__r + "&lt;"
      else
        if web_e__c == ">" then
          let web_e__r = web_e__r + "&gt;"
        else
          let web_e__r = web_e__r + web_e__c
        end
      end
    end
    let web_e__i = web_e__i + 1
  end
  return web_e__r
end

def web_header(t)
  print "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
  print "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
  print "<title>" + t + "</title>"
  print "<style>body{margin:0;font-family:-apple-system,Arial,sans-serif;background:linear-gradient(135deg,#0f172a,#155e75);color:#e2e8f0;padding:28px 16px;min-height:100vh}"
  print ".wrap{max-width:620px;margin:0 auto}.logo{font-weight:700;color:#22d3ee;letter-spacing:.5px}"
  print "h1{font-size:21px;margin:8px 0 16px}.card{background:rgba(30,41,59,.75);border:1px solid rgba(148,163,184,.25);border-radius:12px;padding:14px 16px;margin-bottom:12px}"
  print ".who{color:#22d3ee;font-weight:600}.msg{margin:4px 0 0;line-height:1.5;font-size:14px}"
  print "input,textarea{width:100%;padding:10px;border-radius:8px;border:1px solid rgba(148,163,184,.3);background:rgba(2,6,23,.6);color:#e2e8f0;font-size:14px;margin:4px 0}"
  print "button{padding:9px 16px;border:0;border-radius:8px;background:#0891b2;color:#fff;font-weight:600;cursor:pointer;margin-top:6px}"
  print ".err{color:#fca5a5;font-size:13px}.muted{color:#64748b;font-size:12px;margin-top:22px}</style>"
  print "</head><body><div class=\"wrap\"><div class=\"logo\">ajlangweb</div>"
  print "<h1>" + t + "</h1>"
end

def web_footer()
  print "<p class=\"muted\">powered by ajlangweb on AJOS</p></div></body></html>"
end
