// index.aj - ajlangweb demo: a guestbook (the classic Flask tutorial app)
// Route:  GET/POST /app/index
// Storage: the db package over /tmp/gb.db (subdir path; fat12 write+read
// proven reliable in subdirectories). Ring buffer of 8 entries.

import "web"
import "db"

call web_header("Guestbook")


if web_method() == "POST" then
  let gb__who = web_esc(web_form("who"))
  let gb__msg = web_esc(web_form("msg"))
  if str_len(gb__who) > 0 then
    if str_len(gb__msg) > 0 then
      if str_len(gb__msg) > 110 then
        let gb__msg = str_sub(gb__msg, 0, 110)
      end
      let gb__cnt = num(db_get("/mnt/gb", "count"))
      let gb__slot = gb__cnt % 8 + 1
      db_set("/mnt/gb", "w" + ("" + gb__slot), gb__who)
      db_set("/mnt/gb", "m" + ("" + gb__slot), gb__msg)
      db_set("/mnt/gb", "count", "" + (gb__cnt + 1))
      print "<p>Posted! Thanks, " + gb__who + ".</p>"
    else
      print "<p class=\"err\">Message was empty.</p>"
    end
  else
    print "<p class=\"err\">Name was empty.</p>"
  end
end

print "<div class=\"card\"><form method=\"POST\" action=\"/app/index\">"
print "<input name=\"who\" placeholder=\"Your name\" maxlength=\"32\">"
print "<textarea name=\"msg\" rows=\"3\" maxlength=\"110\" placeholder=\"Say something about AJOS...\"></textarea>"
print "<button type=\"submit\">Post to guestbook</button>"
print "</form></div>"

print "<h1>Entries</h1>"
let gb__i = 8
while gb__i >= 1 do
  let gb__w = db_get("/mnt/gb", "w" + ("" + gb__i))
  if str_len(gb__w) > 0 then
    print "<div class=\"card\"><span class=\"who\">" + gb__w + "</span>"
    print "<p class=\"msg\">" + db_get("/mnt/gb", "m" + ("" + gb__i)) + "</p></div>"
  end
  let gb__i = gb__i - 1
end

call web_footer()
