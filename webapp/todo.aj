// todo.aj - ajlangweb tutorial app: a todo list
// Routes:  GET/POST /app/todo
// Storage: /mnt/todo.db via the db package (ring of 8 items)
// Shows:   forms (GET/POST), query-free action dispatch, escaping,
//          db persistence, loops for rendering, redirect-free flow.

import "web"
import "db"

call web_header("AJLang TODO")

let td__count = num(db_get("/mnt/todo", "count"))

// ---- POST handling: two actions via a hidden field (Flask-style) ----
if web_method() == "POST" then
  let td__action = web_form("action")
  if td__action == "add" then
    let td__title = web_esc(web_form("title"))
    if str_len(td__title) > 0 then
      if str_len(td__title) > 100 then
        let td__title = str_sub(td__title, 0, 100)
      end
      let td__slot = td__count % 8 + 1
      db_set("/mnt/todo", "t" + ("" + td__slot), td__title)
      let td__count = td__count + 1
      db_set("/mnt/todo", "count", "" + td__count)
      print "<p>Added: " + td__title + "</p>"
    else
      print "<p class=\"err\">Empty todo.</p>"
    end
  end
  if td__action == "del" then
    let td__id = web_form("id")
    db_set("/mnt/todo", "t" + td__id, "")
    print "<p>Deleted item " + td__id + ".</p>"
  end
end

// ---- add form ----
print "<div class=\"card\"><form method=\"POST\" action=\"/app/todo\">"
print "<input type=\"hidden\" name=\"action\" value=\"add\">"
print "<input name=\"title\" placeholder=\"New todo...\" maxlength=\"100\">"
print "<button type=\"submit\">Add</button>"
print "</form></div>"

// ---- list, newest first ----
print "<h1>Todos</h1>"
let td__i = 8
while td__i >= 1 do
  let td__t = db_get("/mnt/todo", "t" + ("" + td__i))
  if str_len(td__t) > 0 then
    print "<div class=\"card\"><span>" + td__t + "</span>"
    print "<form method=\"POST\" action=\"/app/todo\" style=\"margin-top:6px\">"
    print "<input type=\"hidden\" name=\"action\" value=\"del\">"
    print "<input type=\"hidden\" name=\"id\" value=\"" + ("" + td__i) + "\">"
    print "<button type=\"submit\">Delete</button></form></div>"
  end
  let td__i = td__i - 1
end

call web_footer()
