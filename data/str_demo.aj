// str_demo.aj - exercise the new /opt/str.aj package.
// Run with:  ajlang str_demo.aj
// See docs/AJLANG.md for import / package details.

import "str"

print "=== str package demo ==="

print "str_starts_with(hello world, hello) -> " + str_starts_with("hello world", "hello")
print "str_starts_with(hello world, world) -> " + str_starts_with("hello world", "world")
print "str_ends_with(hello world, world) -> " + str_ends_with("hello world", "world")
print "str_contains(hello world, lo wo) -> " + str_contains("hello world", "lo wo")
print "str_contains(hello world, xyz) -> " + str_contains("hello world", "xyz")

print "str_trim([  padded  ]) -> [" + str_trim("  padded  ") + "]"

print "str_replace(a-b-c, -, _) -> " + str_replace("a-b-c", "-", "_")

let csv = "readme.txt,42,ok"
print "str_split_count -> " + str_split_count(csv, ",")
print "field 0 -> " + str_split_get(csv, ",", 0)
print "field 1 -> " + str_split_get(csv, ",", 1)
print "field 2 -> " + str_split_get(csv, ",", 2)
print "field 9 (out of range) -> [" + str_split_get(csv, ",", 9) + "]"

print "Done."
