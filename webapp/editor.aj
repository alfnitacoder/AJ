// editor.aj - a tiny in-browser text editor (App Store app)
// Route: /app/editor  (GET renders, POST saves into the RAM db)

import "web"
import "db"

call web_header("AJOS Editor")

let ed__saved = ""
let ed__doc = db_get("/mnt/editor", "doc")

if web_method() == "POST" then
  let ed__new = web_form("doc")
  if str_len(ed__new) > 4000 then
    let ed__new = str_sub(ed__new, 0, 4000)
  end
  db_set("/mnt/editor", "doc", ed__new)
  let ed__doc = ed__new
  let ed__saved = "saved"
end

print "<div class=\"card\">"
if ed__saved == "saved" then
  print "<p style=\"color:#22d3ee\">Saved (" + ("" + num(str_len(ed__doc))) + " chars, lives until reboot).</p>"
end
print "<form method=\"POST\" action=\"/app/editor\">"
print "<textarea name=\"doc\" rows=\"14\" style=\"width:100%;font-family:ui-monospace,Menlo,monospace;font-size:13px;background:rgba(2,6,23,.7);color:#7dd3fc;border:1px solid rgba(148,163,184,.3);border-radius:8px;padding:10px\" placeholder=\"Type anything... it lives in the kernel's RAM db until reboot.\">" + web_esc(ed__doc) + "</textarea>"
print "<p><button type=\"submit\">Save</button> <span style=\"color:#64748b;font-size:12px\">" + ("" + num(str_len(ed__doc))) + "/4000 chars</span></p>"
print "</form></div>"
print "<p style=\"color:#64748b;font-size:12.5px\">Install me on your own AJOS server: <code>appinstall 203.191.130.131 editor</code></p>"

call web_footer()
