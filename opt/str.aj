// str.aj - general-purpose string utilities for AJLang, built entirely on
// the native str_len/str_find/str_sub builtins already used throughout the
// other /opt packages. Fills a real gap: every existing package (see
// db.aj's db_get/db_set/db_list) hand-rolls its own delimiter-scanning
// loop inline; this gives scripts a shared, general version of that same
// logic instead of everyone reimplementing it.
//
// Install:  install opt/str.aj str        (already baked into /opt/str.aj)
// Use:      import "str"
//
// AJLang strings are capped at 255 bytes (see docs/AJLANG.md) -- every
// function here inherits that limit from the str_* builtins it's built on.
// No true local scope: this package's internal variables use a str__
// prefix to avoid colliding with a caller's own names. No `break`
// statement exists, so loops below use an explicit scanning/done flag
// (checked first each iteration) instead of clobbering the position
// variable itself to force an exit -- an earlier draft of str_trim did
// that and silently returned the wrong answer, so it's called out here
// for the next person editing this file.

// True if s starts with prefix.
def str_starts_with(s, prefix)
  let str__plen = str_len(prefix)
  if str_len(s) < str__plen then
    return 0
  end
  if str_sub(s, 0, str__plen) == prefix then
    return 1
  end
  return 0
end

// True if s ends with suffix.
def str_ends_with(s, suffix)
  let str__slen = str_len(s)
  let str__suflen = str_len(suffix)
  if str__slen < str__suflen then
    return 0
  end
  if str_sub(s, str__slen - str__suflen, -1) == suffix then
    return 1
  end
  return 0
end

// True if needle occurs anywhere in s. Thin wrapper over str_find so
// callers testing for presence don't need to remember ">= 0".
def str_contains(s, needle)
  if str_find(s, needle) < 0 then
    return 0
  end
  return 1
end

// Strip leading/trailing ASCII spaces (only " ", not tabs/newlines).
def str_trim(s)
  let str__len = str_len(s)
  let str__start = 0
  let str__scanning = 1
  while str__scanning == 1 do
    if str__start < str__len then
      if str_sub(s, str__start, 1) == " " then
        let str__start = str__start + 1
      else
        let str__scanning = 0
      end
    else
      let str__scanning = 0
    end
  end
  let str__end = str__len
  let str__scanning2 = 1
  while str__scanning2 == 1 do
    if str__end > str__start then
      if str_sub(s, str__end - 1, 1) == " " then
        let str__end = str__end - 1
      else
        let str__scanning2 = 0
      end
    else
      let str__scanning2 = 0
    end
  end
  return str_sub(s, str__start, str__end - str__start)
end

// Replace every non-overlapping occurrence of old with new. If old is ""
// this is a no-op (returns s unchanged) rather than looping forever.
def str_replace(s, old, new)
  let str__oldlen = str_len(old)
  let str__slen = str_len(s)
  let str__result = ""
  let str__pos = 0
  if str__oldlen == 0 then
    return s
  end
  while str__pos < str__slen do
    let str__rest = str_sub(s, str__pos, -1)
    let str__idx = str_find(str__rest, old)
    if str__idx < 0 then
      let str__result = str__result + str__rest
      let str__pos = str__slen
    else
      let str__result = str__result + str_sub(str__rest, 0, str__idx) + new
      let str__pos = str__pos + str__idx + str__oldlen
    end
  end
  return str__result
end

// Number of delim-separated fields in s (AJLang has no array type, so
// str_split_count/str_split_get are the way to walk a delimited string --
// e.g. a CSV line or a "a,b,c" list -- by index instead). A delimiter
// sitting at the very end of s does not count a trailing empty field
// (str_split_count("a,b,", ",") is 2, not 3) -- same convention db_list
// already uses for a trailing newline, kept consistent here.
def str_split_count(s, delim)
  let str__dlen = str_len(delim)
  let str__slen = str_len(s)
  let str__pos = 0
  let str__count = 0
  while str__pos < str__slen do
    let str__rest = str_sub(s, str__pos, -1)
    let str__idx = str_find(str__rest, delim)
    let str__adv = 0
    if str__idx < 0 then
      let str__adv = str__slen - str__pos
    else
      let str__adv = str__idx + str__dlen
    end
    let str__count = str__count + 1
    let str__pos = str__pos + str__adv
  end
  return str__count
end

// The index-th delim-separated field of s (0-based), or "" if index is
// out of range. See str_split_count for the trailing-delimiter convention.
def str_split_get(s, delim, index)
  let str__dlen = str_len(delim)
  let str__slen = str_len(s)
  let str__pos = 0
  let str__cur = 0
  let str__result = ""
  while str__pos < str__slen do
    let str__rest = str_sub(s, str__pos, -1)
    let str__idx = str_find(str__rest, delim)
    let str__field = ""
    let str__adv = 0
    if str__idx < 0 then
      let str__field = str__rest
      let str__adv = str__slen - str__pos
    else
      let str__field = str_sub(str__rest, 0, str__idx)
      let str__adv = str__idx + str__dlen
    end
    if str__cur == index then
      let str__result = str__field
    end
    let str__cur = str__cur + 1
    let str__pos = str__pos + str__adv
  end
  return str__result
end
