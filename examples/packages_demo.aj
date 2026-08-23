// packages_demo.aj - exercise the /opt/ package system (http + db)
// Run with:  ajlang packages_demo.aj
// See docs/AJLANG.md for import / package details.

import "http"
import "db"

print "=== AJLang packages demo ==="

db_set("demo", "name", "ajos")
db_set("demo", "lang", "ajlang")
print "db_get name -> " + db_get("demo", "name")
print "db_get lang -> " + db_get("demo", "lang")
print "db_list:"
db_list("demo")

print "Fetching http://example.com/ ..."
let page = http_fetch("http://example.com/")
print page

print "Done."
