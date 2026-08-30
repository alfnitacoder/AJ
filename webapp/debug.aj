// debug.aj - isolate the ajlangweb POST-conditional bug (with db import)
import "web"
import "db"

print "<pre>"
print "M1=[" + web_method() + "]"
if web_method() == "POST" then
  print "C1_inline_if_RAN"
end
let gb__cnt = num(db_get("/mnt/gb", "count"))
print "CNT=[" + gb__cnt + "]"
let gb__slot = gb__cnt % 8 + 1
print "SLOT=[" + gb__slot + "]"
db_set("/mnt/gb", "w" + ("" + gb__slot), "dbgwho")
let gb__w = db_get("/mnt/gb", "w" + ("" + gb__slot))
print "W=[" + gb__w + "]"
let t1 = str_len(web_form("x"))
print "T1=[" + t1 + "]"
if web_method() == "POST" then
  let e1 = web_esc(web_form("x"))
  print "ESC=[" + e1 + "]"
  if t1 > 0 then
    print "NESTED_RAN"
  else
    print "NESTED_ELSE_RAN"
  end
end
print "KEY=[" + ("w" + ("" + gb__slot)) + "]"
if web_method() == "POST" then
  print "C2_late_if_RAN"
end
print "</pre>"
