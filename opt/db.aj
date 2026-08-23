// db.aj - a minimal pure-AJLang key/value store over a flat file of
// "key=value" lines, one file per db name (e.g. db "test" -> test.db in
// the current directory). Built entirely on file_read/file_write/
// str_len/str_find/str_sub -- no new native code, just to prove the
// import mechanism works for an ordinary library, not only C builtins.
//
// Install:  install opt/db.aj db        (already baked into /opt/db.aj)
// Use:      import "db"
//
// Limitation: AJLang strings are capped at 255 bytes, and file_read
// truncates at that size too, so a db file (all its "key=value\n" lines
// together) can only hold a couple dozen short entries before it starts
// silently losing data. Fine for config/demo use, not a real database.
// AJLang has no true local scope (see docs/AJLANG.md) and every
// assignment -- even reassigning an existing variable inside an if/while
// body -- must go through `let` (there is no bare `x = y` statement).
// This package's internal variables use a db__ prefix to avoid colliding
// with names a caller's own script happens to use.

def db_set(name, key, value)
  let db__path = name + ".db"
  let db__content = file_read(db__path)
  let db__prefix = key + "="
  let db__plen = str_len(db__prefix)
  let db__clen = str_len(db__content)
  let db__pos = 0
  let db__result = ""
  let db__replaced = 0
  while db__pos < db__clen do
    let db__rest = str_sub(db__content, db__pos, -1)
    let db__nl = str_find(db__rest, "\n")
    let db__line = ""
    let db__adv = 0
    if db__nl < 0 then
      let db__line = db__rest
      let db__adv = db__clen - db__pos
    else
      let db__line = str_sub(db__rest, 0, db__nl)
      let db__adv = db__nl + 1
    end
    if str_len(db__line) >= db__plen then
      if str_sub(db__line, 0, db__plen) == db__prefix then
        let db__line = db__prefix + value
        let db__replaced = 1
      end
    end
    if str_len(db__line) > 0 then
      let db__result = db__result + db__line + "\n"
    end
    let db__pos = db__pos + db__adv
  end
  if db__replaced == 0 then
    let db__result = db__result + db__prefix + value + "\n"
  end
  return file_write(db__path, db__result)
end

def db_get(name, key)
  let db__path = name + ".db"
  let db__content = file_read(db__path)
  let db__prefix = key + "="
  let db__plen = str_len(db__prefix)
  let db__clen = str_len(db__content)
  let db__pos = 0
  let db__found = ""
  while db__pos < db__clen do
    let db__rest = str_sub(db__content, db__pos, -1)
    let db__nl = str_find(db__rest, "\n")
    let db__line = ""
    let db__adv = 0
    if db__nl < 0 then
      let db__line = db__rest
      let db__adv = db__clen - db__pos
    else
      let db__line = str_sub(db__rest, 0, db__nl)
      let db__adv = db__nl + 1
    end
    if str_len(db__line) >= db__plen then
      if str_sub(db__line, 0, db__plen) == db__prefix then
        let db__found = str_sub(db__line, db__plen, -1)
      end
    end
    let db__pos = db__pos + db__adv
  end
  return db__found
end

// Prints every key currently stored in db "name", one per line.
def db_list(name)
  let db__path = name + ".db"
  let db__content = file_read(db__path)
  let db__clen = str_len(db__content)
  let db__pos = 0
  while db__pos < db__clen do
    let db__rest = str_sub(db__content, db__pos, -1)
    let db__nl = str_find(db__rest, "\n")
    let db__line = ""
    let db__adv = 0
    if db__nl < 0 then
      let db__line = db__rest
      let db__adv = db__clen - db__pos
    else
      let db__line = str_sub(db__rest, 0, db__nl)
      let db__adv = db__nl + 1
    end
    if str_len(db__line) > 0 then
      let db__eq = str_find(db__line, "=")
      if db__eq >= 0 then
        print str_sub(db__line, 0, db__eq)
      end
    end
    let db__pos = db__pos + db__adv
  end
end
