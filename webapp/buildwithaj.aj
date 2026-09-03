// buildwithaj.aj - AJOS.dev : the official AJOS + AJLang developer site
// Runs on ajlangweb. Route: /app/buildwithaj?page=<section>

import "web"

let bw__pg = web_query("page")
if str_len(bw__pg) == 0 then
  let bw__pg = "home"
end

// ---- shared page chrome with buildwithAJ nav ----
print "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
print "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
print "<title>buildwithAJ - AJOS.dev</title>"
print "<style>body{margin:0;font-family:-apple-system,Arial,sans-serif;background:#0b1220;color:#e2e8f0}"
print "nav{position:sticky;top:0;background:rgba(11,18,32,.92);border-bottom:1px solid rgba(148,163,184,.2);padding:12px 20px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}"
print ".brand{font-weight:800;font-size:17px;color:#f1f5f9}.brand b{color:#22d3ee}"
print "nav a{color:#94a3b8;font-size:13.5px;text-decoration:none}nav a:hover{color:#22d3ee}"
print ".hero{padding:52px 20px 30px;text-align:center;background:linear-gradient(180deg,rgba(34,211,238,.08),transparent)}"
print "h1{font-size:34px;margin:0 0 10px;color:#f1f5f9}h1 b{color:#22d3ee}"
print ".tag{color:#94a3b8;font-size:15px;max-width:560px;margin:0 auto}"
print ".wrap{max-width:860px;margin:0 auto;padding:10px 20px 60px}"
print "h2{font-size:20px;color:#22d3ee;margin:34px 0 10px;border-bottom:1px solid rgba(148,163,184,.15);padding-bottom:6px}"
print "p,li{font-size:14.5px;line-height:1.65;color:#cbd5e1}"
print "code,pre{font-family:ui-monospace,Menlo,monospace;font-size:13px}"
print "pre{background:rgba(2,6,23,.7);border:1px solid rgba(148,163,184,.2);border-radius:10px;padding:14px;overflow-x:auto;color:#7dd3fc}"
print "code.inl{background:rgba(34,211,238,.12);color:#67e8f9;padding:1px 5px;border-radius:5px}"
print ".cards{display:flex;flex-wrap:wrap;gap:12px;margin-top:14px}"
print ".c{flex:1 1 240px;background:rgba(30,41,59,.6);border:1px solid rgba(148,163,184,.2);border-radius:12px;padding:14px 16px}"
print ".c b{color:#f1f5f9}.c p{margin:6px 0 0;font-size:13px;color:#94a3b8}"
print "a.lk{color:#22d3ee;text-decoration:none}a.lk:hover{text-decoration:underline}"
print ".ft{margin-top:40px;padding:18px;text-align:center;color:#475569;font-size:12px;border-top:1px solid rgba(148,163,184,.12)}"
print "table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:10px}"
print "td,th{border:1px solid rgba(148,163,184,.18);padding:7px 10px;text-align:left}th{color:#7dd3fc}</style>"
print "</head><body>"
print "<nav><span class=\"brand\">buildwith<b>AJ</b></span>"
print "<a href=\"/app/buildwithaj\">Home</a>"
print "<a href=\"/app/buildwithaj?page=ajos-download\">AJOS</a>"
print "<a href=\"/app/buildwithaj?page=ajlang-language\">AJLang</a>"
print "<a href=\"/app/buildwithaj?page=dev-build\">Developers</a>"
print "<a href=\"/app/buildwithaj?page=apps-store\">Apps</a>"
print "<a href=\"/app/buildwithaj?page=com-forum\">Community</a></nav>"
print "<div class=\"hero\"><h1>AJOS.dev - build with <b>AJ</b></h1>"
print "<p class=\"tag\">A 32-bit operating system with its own kernel, filesystem, TCP/IP stack, SSH server and the AJLang scripting language. Written from scratch.</p></div>"
print "<div class=\"wrap\">"

// ================= HOME =================
if bw__pg == "home" then
  print "<div class=\"cards\">"
  print "<div class=\"c\"><b>AJOS</b><p>A 32-bit i386 kernel: FAT12 filesystem, TCP/IP, SSH/SFTP, HTTP server, processes with fork/execve.</p><a class=\"lk\" href=\"/app/buildwithaj?page=ajos-features\">Features -</a></div>"
  print "<div class=\"c\"><b>AJLang</b><p>A scripting language built into the kernel: functions, loops, packages, file and network builtins. Flask-style web apps via ajlangweb.</p><a class=\"lk\" href=\"/app/buildwithaj?page=ajlang-language\">The language -</a></div>"
  print "<div class=\"c\"><b>Developers</b><p>Build, run and ship apps: one make, one script, live at /app/yourapp. SDK tools included.</p><a class=\"lk\" href=\"/app/buildwithaj?page=dev-build\">Start building -</a></div>"
  print "<div class=\"c\"><b>Apps</b><p>The AJOS App Store: guestbook, todo, portal - packaged as importable AJLang packages.</p><a class=\"lk\" href=\"/app/buildwithaj?page=apps-store\">Browse apps -</a></div>"
  print "<div class=\"c\"><b>Community</b><p>Forum, source code and the people building AJ.</p><a class=\"lk\" href=\"/app/buildwithaj?page=com-github\">Join in -</a></div>"
  print "</div>"
end

// ================= AJOS =================
if bw__pg == "ajos-download" then
  print "<h2>AJOS / Download</h2>"
  print "<p>AJOS boots from a 1.44 MB floppy image in QEMU, VirtualBox or Proxmox (SeaBIOS + Intel E1000).</p>"
  print "<pre>git clone &lt;your-repo-url&gt; ajos"
  print "cd ajos &amp;&amp; make          # builds kernel + boot floppy"
  print "./run_aj.sh start        # boots the guest (SSH :9022, web :9080)</pre>"
  print "<p>Requires QEMU (host) and i386-elf binutils for the kernel build.</p>"
  print "<p>Prebuilt artifacts: <code class=\"inl\">build/ajos.img</code> (boot floppy) and <code class=\"inl\">build/data.img</code> (32 MB IDE disk for apps and data).</p>"
end
if bw__pg == "ajos-features" then
  print "<h2>AJOS / Features</h2>"
  print "<div class=\"cards\">"
  print "<div class=\"c\"><b>32-bit kernel</b><p>Protected mode, GDT/IDT, Paging + PMM buddy allocator, slab allocator, preemptive processes with fork/execve/waitpid.</p></div>"
  print "<div class=\"c\"><b>Filesystems</b><p>FAT12 read/write with nested paths, VFS layer, ramfs, secondary IDE disk mounted at /mnt.</p></div>"
  print "<div class=\"c\"><b>Networking</b><p>E1000 driver, ARP/IPv4/ICMP/TCP/UDP, DHCP client+server, DNS resolver and server.</p></div>"
  print "<div class=\"c\"><b>Servers</b><p>SSH server (RSA-2048, AES-CTR), SFTP, HTTP server, syslog. The OS serves its own website - this page.</p></div>"
  print "<div class=\"c\"><b>AJLang</b><p>In-kernel scripting: packages, files, networking, and ajlangweb for web apps.</p></div>"
  print "<div class=\"c\"><b>Developer loop</b><p>Edit - make - live: scripts are baked into the image and served instantly.</p></div>"
  print "</div>"
end
if bw__pg == "ajos-docs" then
  print "<h2>AJOS / Documentation</h2>"
  print "<p>The documentation set lives in the repository under <code class=\"inl\">docs/</code>:</p>"
  print "<table><tr><th>Doc</th><th>Covers</th></tr>"
  print "<tr><td>AJLANG.md</td><td>The AJLang language, packages, native builtins</td></tr>"
  print "<tr><td>AJLANGWEB.md</td><td>The ajlangweb framework (this site runs on it)</td></tr>"
  print "<tr><td>MEMORY.md</td><td>Kernel memory: kmalloc, PMM, leak hunting</td></tr>"
  print "<tr><td>PROXMOX.md</td><td>Running AJOS on Proxmox VE</td></tr>"
  print "<tr><td>TESTING_CRYPTO.md</td><td>Crypto self-tests for SSH</td></tr></table>"
  print "<p>Kernel sources are in <code class=\"inl\">src/</code> (network, fs, ssh, http, ajlang) and <code class=\"inl\">kernel/</code> (mm).</p>"
end
if bw__pg == "ajos-roadmap" then
  print "<h2>AJOS / Roadmap</h2>"
  print "<p><b>Shipped:</b> TCP/IP stack, SSH + SFTP, HTTP server, AJLang + packages, ajlangweb, processes, syslog, IDE storage.</p>"
  print "<p><b>Next:</b></p>"
  print "<li>Montgomery multiplication for instant SSH handshakes</li>"
  print "<li>Persistent app installs and the AJOS App Store</li>"
  print "<li>More AJLang stdlib: string builder, JSON, timers</li>"
  print "<li>ELF-style userspace binaries and a libc subset</li>"
  print "<li>VFS journaling for the IDE disk</li>"
end

// ================= AJLANG =================
if bw__pg == "ajlang-language" then
  print "<h2>AJLang / Language</h2>"
  print "<p>AJLang is a small, readable scripting language interpreted inside the AJOS kernel. Hello world:</p>"
  print "<pre>import \"web\""
  print "call web_header(\"Hello\")"
  print "let name = web_form(\"name\")"
  print "if str_len(name) &gt; 0 then"
  print "  print \"&lt;p&gt;Hi \" + web_esc(name) + \"!&lt;/p&gt;\""
  print "else"
  print "  print \"&lt;p&gt;Hello, world.&lt;/p&gt;\""
  print "end"
  print "call web_footer()</pre>"
  print "<p>Statements: <code class=\"inl\">print let if/else/end while/do/end for/to/do/end def/return</code>. Operators: <code class=\"inl\">+ - * / % == != &lt; &gt; and or not</code>.</p>"
  print "<p>Every variable lives in one global table; strings are capped at 255 bytes - print incrementally for larger output.</p>"
  print "<h3>Language features</h3>"
  print "<div class=\"cards\">"
  print "<div class=\"c\"><b>Functions</b><p><code class=\"inl\">def name(a, b)</code> with <code class=\"inl\">return</code> - recursion works (factorial, fib).</p></div>"
  print "<div class=\"c\"><b>Control flow</b><p><code class=\"inl\">if/elif/else/end</code>, <code class=\"inl\">while/do/end</code>, <code class=\"inl\">for i = 0 to 10 do/end</code>.</p></div>"
  print "<div class=\"c\"><b>Packages</b><p><code class=\"inl\">import \\"web\\"</code> loads /opt/web.aj - share code across every app.</p></div>"
  print "<div class=\"c\"><b>Kernel access</b><p>file_read/file_write over the VFS, http_get for outbound web calls, dns lookups - from a script.</p></div>"
  print "<div class=\"c\"><b>Web framework</b><p>ajlangweb: routes, forms, query strings, escaping, redirects - Flask-style, zero config.</p></div>"
  print "<div class=\"c\"><b>Storage</b><p>db package: key/value sets and gets persisted in the kernel, addressable by app namespace.</p></div>"
  print "</div>"
end
if bw__pg == "ajlang-docs" then
  print "<h2>AJLang / Documentation</h2>"
  print "<p>The complete language and runtime reference - everything a script can call, served from the kernel itself. The long-form documents also live in the repo: <code class=\"inl\">docs/AJLANG.md</code> and <code class=\"inl\">docs/AJLANGWEB.md</code>.</p>"

  print "<h3>Syntax</h3>"
  print "<table><tr><th>Construct</th><th>Form</th></tr>"
  print "<tr><td>Variable</td><td><code class=\"inl\">let x = 42</code> - one global table, dynamic types</td></tr>"
  print "<tr><td>Branch</td><td><code class=\"inl\">if c then ... elif c2 then ... else ... end</code></td></tr>"
  print "<tr><td>Loop</td><td><code class=\"inl\">while c do ... end</code> / <code class=\"inl\">for i = 0 to 9 do ... end</code></td></tr>"
  print "<tr><td>Function</td><td><code class=\"inl\">def add(a, b) ... return a + b end</code></td></tr>"
  print "<tr><td>Call</td><td><code class=\"inl\">call web_header(\"Title\")</code> or use the value inline</td></tr>"
  print "<tr><td>Output</td><td><code class=\"inl\">print \"text\"</code> - streams straight to the HTTP response</td></tr>"
  print "<tr><td>Import</td><td><code class=\"inl\">import \"db\"</code> - loads a package from /opt/</td></tr>"
  print "<tr><td>Comment</td><td><code class=\"inl\">// to end of line</code></td></tr>"
  print "<tr><td>Operators</td><td><code class=\"inl\">+ - * / % == != &lt; &gt; and or not</code></td></tr></table>"

  print "<h3>Native built-ins</h3>"
  print "<table><tr><th>Built-in</th><th>What it does</th></tr>"
  print "<tr><td>str_len(s)</td><td>String length in bytes</td></tr>"
  print "<tr><td>str_find(s, needle)</td><td>Index of needle in s, or -1</td></tr>"
  print "<tr><td>str_sub(s, start, len)</td><td>Substring slice</td></tr>"
  print "<tr><td>num(x)</td><td>Coerce to a number (from db strings, form input)</td></tr>"
  print "<tr><td>file_read(path)</td><td>Read a file through the VFS (floppy, /mnt IDE disk)</td></tr>"
  print "<tr><td>file_write(path, text)</td><td>Write a file through the VFS</td></tr>"
  print "<tr><td>http_get(url)</td><td>Outbound HTTP GET - fetch any page from the script</td></tr>"
  print "<tr><td>http_get_save(url, path)</td><td>Fetch and save to a file</td></tr>"
  print "<tr><td>dns(name)</td><td>Resolve a hostname to an IP</td></tr>"
  print "<tr><td>edit(path)</td><td>Open the built-in fullscreen editor</td></tr></table>"

  print "<h3>ajlangweb request built-ins</h3>"
  print "<table><tr><th>Built-in</th><th>What it does</th></tr>"
  print "<tr><td>web_method()</td><td>\"GET\" or \"POST\"</td></tr>"
  print "<tr><td>web_path()</td><td>Request path without the query string</td></tr>"
  print "<tr><td>web_query(\"k\")</td><td>Query-string parameter</td></tr>"
  print "<tr><td>web_form(\"k\")</td><td>POST form field</td></tr>"
  print "<tr><td>web_redirect(url)</td><td>Send an HTTP redirect instead of a page</td></tr></table>"

  print "<h3>Packages (/opt/)</h3>"
  print "<table><tr><th>Package</th><th>Exports</th></tr>"
  print "<tr><td>web</td><td>web_header(title), web_footer(), web_esc(s) - HTML escaping</td></tr>"
  print "<tr><td>db</td><td>db_set(store, key, val), db_get(store, key), db_list(store) - persistent key/value</td></tr>"
  print "<tr><td>str</td><td>str_contains, str_starts_with, str_ends_with, str_trim, str_replace, str_split_get</td></tr>"
  print "<tr><td>http</td><td>http_fetch(url), http_fetch_save(url, path)</td></tr>"
  print "<tr><td>editor</td><td>edit_file(path)</td></tr></table>"

  print "<h3>Limits</h3>"
  print "<p>Strings: 255 bytes each (print incrementally for long output). Script: 4096 tokens. One global variable table per run. Apps are single files at <code class=\"inl\">webapp/&lt;name&gt;.aj</code>, routed at <code class=\"inl\">/app/&lt;name&gt;</code>.</p>"
  print "<p>The interpreter is <code class=\"inl\">src/ajlang.c</code> - about 1300 lines of C, readable in one sitting.</p>"
end
if bw__pg == "ajlang-tutorials" then
  print "<h2>AJLang / Tutorials</h2>"
  print "<p><b>1. Your first script.</b> Create <code class=\"inl\">examples/hello.aj</code>:</p>"
  print "<pre>print \"Hello from AJLang on AJOS!\""
  print "let x = 42"
  print "print \"The answer is \" + x</pre>"
  print "<p><b>2. Functions and loops.</b> See <code class=\"inl\">examples/functions.aj</code>: def/return, recursion (factorial), while and for loops.</p>"
  print "<p><b>3. Packages.</b> <code class=\"inl\">examples/packages_demo.aj</code> imports the http and db packages: fetch a page, store and read key/value data.</p>"
  print "<p><b>4. A web app.</b> Read <code class=\"inl\">webapp/index.aj</code> - a complete guestbook with forms, storage and escaping - then copy it and make it yours.</p>"
end
if bw__pg == "ajlang-stdlib" then
  print "<h2>AJLang / Standard Library</h2>"
  print "<p>Packages live in <code class=\"inl\">/opt/&lt;name&gt;.aj</code> and are loaded with <code class=\"inl\">import \"name\"</code>:</p>"
  print "<table><tr><th>Package</th><th>Exports</th></tr>"
  print "<tr><td>web</td><td>web_header, web_footer, web_esc, web_route</td></tr>"
  print "<tr><td>db</td><td>db_set, db_get, db_list - flat-file key/value store</td></tr>"
  print "<tr><td>http</td><td>http_fetch, http_fetch_save</td></tr>"
  print "<tr><td>editor</td><td>edit_file - opens the built-in editor</td></tr></table>"
  print "<p>Native builtins: <code class=\"inl\">str_len str_find str_sub file_read file_write http_get dns num</code> and the ajlangweb request set: <code class=\"inl\">web_method web_path web_query web_form web_redirect</code>.</p>"
end

// ================= DEVELOPERS =================
if bw__pg == "dev-build" then
  print "<h2>Developers / Build Apps</h2>"
  print "<p>An ajlangweb app is one file in <code class=\"inl\">webapp/</code>. The build bakes it into the disk image; the HTTP server maps /app/&lt;name&gt; to it.</p>"
  print "<pre>webapp/guest.aj      ->  /app/guest"
  print "webapp/todo.aj       ->  /app/todo</pre>"
  print "<p>Build and restart:</p>"
  print "<pre>make                 # kernel + images (apps included)"
  print "./run_aj.sh stop &amp;&amp; ./run_aj.sh start</pre>"
  print "<p>Your app is live at /app/&lt;name&gt;. State persists on the IDE disk under /mnt/.</p>"
end
if bw__pg == "dev-sdk" then
  print "<h2>Developers / SDK</h2>"
  print "<p>The repo ships the whole toolchain:</p>"
  print "<table><tr><th>Tool</th><th>Purpose</th></tr>"
  print "<tr><td>run_aj.sh</td><td>Launch / status / stop the guest VM (launchd keep-alive)</td></tr>"
  print "<tr><td>tools/ajos_dev.sh</td><td>push / pull / run / sync files over SFTP</td></tr>"
  print "<tr><td>tools/mkfat12.py</td><td>Builds FAT images and stages apps + packages</td></tr>"
  print "<tr><td>test_sftp.sh</td><td>End-to-end transport test</td></tr></table>"
  print "<p>Editors: Cursor/VS Code tasks for push-and-run are included (.vscode/tasks.json).</p>"
end
if bw__pg == "dev-api" then
  print "<h2>Developers / API</h2>"
  print "<p>Two APIs meet in an ajlangweb app:</p>"
  print "<p><b>Request API</b> (injected by the server): <code class=\"inl\">web_method() web_path() web_query(k) web_form(k) web_redirect(loc)</code>.</p>"
  print "<p><b>Storage API</b> (db package): <code class=\"inl\">db_set(name,k,v) db_get(name,k) db_list(name)</code> - values persist on the IDE disk.</p>"
  print "<p><b>System API</b> (native): <code class=\"inl\">file_read file_write http_get dns str_* num</code>.</p>"
  print "<p>Responses are just <code class=\"inl\">print</code>: everything your script prints between web_header and web_footer is the HTTP body.</p>"
end
if bw__pg == "dev-examples" then
  print "<h2>Developers / Examples</h2>"
  print "<li><b>hello.aj</b> - print, variables, string concat</li>"
  print "<li><b>fib.aj</b> - loops and arithmetic</li>"
  print "<li><b>functions.aj</b> - def/return, recursion</li>"
  print "<li><b>conditions.aj</b> - if/else, booleans, and/or/not</li>"
  print "<li><b>packages_demo.aj</b> - import, http + db packages</li>"
  print "<li><b>input_demo.aj</b> - reading input</li>"
  print "<li><b>webapp/index.aj</b> - full web app: guestbook with db + escaping</li>"
  print "<li><b>webapp/todo.aj</b> - todo list: add/delete actions, ring storage</li>"
  print "<p>All in the repository <code class=\"inl\">examples/</code> and <code class=\"inl\">webapp/</code> folders.</p>"
end

// ================= APPS =================
if bw__pg == "apps-store" then
  print "<h2>Apps / AJOS App Store</h2>"
  print "<p>Apps are AJLang packages and webapp scripts. Install one by copying it into the image (or <code class=\"inl\">install &lt;file&gt; &lt;name&gt;</code> for packages):</p>"
  print "<pre>webapp/guest.aj   ->  /app/guest   (web apps)"
  print "opt/cool.aj       ->  import \"cool\" (libraries)</pre>"
  print "<p><b>In the store today:</b></p>"
  print "<div class=\"cards\">"
  print "<div class=\"c\"><b>Guestbook</b><p>Sign and browse messages, stored on the IDE disk. <a class=\"lk\" href=\"/app/index\">Open -</a></p></div>"
  print "<div class=\"c\"><b>TODO</b><p>Add and delete todos, ring storage. <a class=\"lk\" href=\"/app/todo\">Open -</a></p></div>"
  print "<div class=\"c\"><b>Captive portal</b><p>WiFi-style login on the root route. <a class=\"lk\" href=\"/\">Open -</a></p></div>"
  print "</div>"
  print "<p>Ship yours: drop a script in webapp/, run make, done.</p>"
end

// ================= COMMUNITY =================
if bw__pg == "com-forum" then
  print "<h2>Community / Forum</h2>"
  print "<p>Questions, ideas and show-and-tell live in the repository discussions. Ask anything - from bootloader quirks to AJLang one-liners.</p>"
  print "<p>Good first questions: how does the VFS route /mnt, how does the SSH handshake work, what breaks when you print more than 255 bytes?</p>"
end
if bw__pg == "com-github" then
  print "<h2>Community / GitHub</h2>"
  print "<p>The whole OS - kernel, interpreter, servers, docs, this website - is one repository:</p>"
  print "<pre>ajos/"
  print "  src/        kernel + servers + AJLang interpreter"
  print "  kernel/     memory management"
  print "  opt/        AJLang packages (web, db, http, editor)"
  print "  webapp/     ajlangweb apps (this site!)"
  print "  examples/   language tutorials"
  print "  docs/       documentation</pre>"
  print "<p>Add your fork URL to this page when the repo goes public.</p>"
end
if bw__pg == "com-contribs" then
  print "<h2>Community / Contributors</h2>"
  print "<p>AJOS is built by a human + AI pair: kernel and language designed iteratively, with the AI implementing, testing and debugging over SSH - the SSH server you just used was built and fixed by this loop.</p>"
  print "<p>Contributions wanted: AJLang stdlib modules, example apps, docs, and the App Store catalog.</p>"
end

print "<div class=\"ft\">AJOS.dev - build with AJ - served by the AJOS HTTP server, rendered by ajlangweb</div>"
print "</div></body></html>"
