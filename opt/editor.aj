// editor.aj - AJLang package wrapping the native full-screen editor.
// Install:  install opt/editor.aj editor   (already baked into /opt/editor.aj)
// Use:      import "editor"

// Opens `path` in the AJOS editor (same as the shell's `edit` command).
def edit_file(path)
  edit(path)
end
