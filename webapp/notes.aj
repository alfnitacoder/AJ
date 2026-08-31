// notes.aj - store-exclusive app: proves the appinstall flow end-to-end
// Route: /app/notes

import "web"
import "db"

call web_header("Notes")

let nt__doc = db_get("/mnt/notes", "doc")
if web_method() == "POST" then
  let nt__new = web_form("doc")
  if str_len(nt__new) > 3000 then
    let nt__new = str_sub(nt__new, 0, 3000)
  end
  db_set("/mnt/notes", "doc", nt__new)
  let nt__doc = nt__new
  print "<div class=\\"card\\"><p style=\\"color:#22d3ee\\">Saved!</p></div>"
end

print "<div class=\\"card\\"><form method=\\"POST\\" action=\\"/app/notes\\">"
print "<textarea name=\\"doc\\" rows=\\"10\\" style=\\"width:100%;font-family:ui-monospace,Menlo,monospace;font-size:13px;background:rgba(2,6,23,.7);color:#7dd3fc;border:1px solid rgba(148,163,184,.3);border-radius:8px;padding:10px\\" placeholder=\\"Your notes...\\">" + web_esc(nt__doc) + "</textarea>"
print "<p><button type=\\"submit\\">Save note</button></p>"
print "</form></div>"
print "<p style=\\"color:#64748b;font-size:12.5px\\">This app was installed from the AJOS App Store at runtime - it is not in the boot image.</p>"

call web_footer()
