// store.aj - The AJOS App Store
// The official catalog of apps for AJOS + ajlangweb.
// Route: /app/store  (also the landing page of the store server)

import "web"

let st__pg = web_query("page")
if str_len(st__pg) == 0 then
  let st__pg = "home"
end

// ---- chrome (matches the AJOS.dev / buildwithAJ brand) ----
print "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
print "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
print "<title>AJOS App Store</title>"
print "<style>body{margin:0;font-family:-apple-system,Arial,sans-serif;background:#0b1220;color:#e2e8f0}"
print "nav{position:sticky;top:0;background:rgba(11,18,32,.94);border-bottom:1px solid rgba(148,163,184,.2);padding:12px 20px;display:flex;gap:16px;align-items:center;flex-wrap:wrap}"
print ".brand{font-weight:800;font-size:17px;color:#f1f5f9}.brand b{color:#22d3ee}"
print "nav a{color:#94a3b8;font-size:13.5px;text-decoration:none}nav a:hover{color:#22d3ee}"
print ".hero{padding:46px 20px 26px;text-align:center;background:linear-gradient(180deg,rgba(34,211,238,.09),transparent)}"
print "h1{font-size:32px;margin:0 0 8px;color:#f1f5f9}h1 b{color:#22d3ee}"
print ".tag{color:#94a3b8;font-size:14.5px;max-width:560px;margin:0 auto}"
print ".wrap{max-width:860px;margin:0 auto;padding:6px 20px 60px}"
print "h2{font-size:20px;color:#22d3ee;margin:32px 0 10px;border-bottom:1px solid rgba(148,163,184,.15);padding-bottom:6px}"
print "p,li{font-size:14px;line-height:1.65;color:#cbd5e1}"
print ".cards{display:flex;flex-wrap:wrap;gap:12px;margin-top:14px}"
print ".c{flex:1 1 250px;background:rgba(30,41,59,.6);border:1px solid rgba(148,163,184,.2);border-radius:12px;padding:14px 16px}"
print ".c h3{margin:0 0 4px;font-size:15.5px;color:#f1f5f9}"
print ".c p{margin:4px 0 8px;font-size:13px;color:#94a3b8}"
print ".pill{display:inline-block;background:rgba(34,211,238,.14);color:#67e8f9;font-size:11px;border-radius:999px;padding:2px 9px;margin-right:5px}"
print "a.btn{display:inline-block;background:#22d3ee;color:#04141c;font-weight:700;font-size:12.5px;text-decoration:none;border-radius:8px;padding:6px 12px}"
print "code,pre{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}"
print "pre{background:rgba(2,6,23,.7);border:1px solid rgba(148,163,184,.2);border-radius:10px;padding:12px;overflow-x:auto;color:#7dd3fc}"
print ".foot{color:#64748b;font-size:12px;text-align:center;padding:22px;border-top:1px solid rgba(148,163,184,.12);margin-top:30px}"
print "</style></head><body>"

print "<nav><span class=\"brand\">AJOS <b>App Store</b></span>"
print "<a href=\"/app/store\">Store</a>"
print "<a href=\"/app/store?page=publish\">Publish</a>"
print "<a href=\"/app/buildwithaj\">AJOS.dev</a>"
print "<a href=\"/app/index\">Guestbook</a>"
print "<a href=\"/app/todo\">TODO</a></nav>"

if st__pg == "publish" then
  print "<div class=\"hero\"><h1>Publish an <b>app</b></h1>"
  print "<div class=\"tag\">Every AJOS app is one AJLang script in the image's webapp/ directory.</div></div>"
  print "<div class=\"wrap\">"
  print "<h2>1. Write the script</h2>"
  print "<p>An app is a single <code>.aj</code> file. Use the <code>web</code> helpers and print HTML:</p>"
  print "<pre>import \"web\"\ncall web_header(\"Hello\")\nprint \"&lt;p&gt;Hi from \" + web_esc(web_query(\"name\")) + \"!&lt;/p&gt;\"\ncall web_footer()</pre>"
  print "<h2>2. Drop it into webapp/</h2>"
  print "<p>The HTTP server maps <code>/app/&lt;name&gt;</code> to <code>webapp/&lt;name&gt;.aj</code> in the boot image.</p>"
  print "<h2>3. Bake + install</h2>"
  print "<pre># rebuild the boot image with your app staged\npython3 tools/mkfat12.py build/ajos.img --boot build/boot.bin --kernel build/kernel.bin\n# flash it to the primary disk from the AJOS shell\ninstalldisk</pre>"
  print "<h2>4. Share it</h2>"
  print "<p>Post your app in the <a href=\"/app/index\" style=\"color:#67e8f9\">guestbook</a> and the community can grab the recipe. No package manager, no manifest, no dependency hell - one file, one route.</p>"
  print "</div>"
else
  print "<div class=\"hero\"><h1>AJOS <b>App Store</b></h1>"
  print "<div class=\"tag\">Tiny, honest apps for the smallest web server on the internet. Every app runs inside the AJOS kernel's AJLang interpreter.</div></div>"
  print "<div class=\"wrap\">"

  print "<h2>Featured</h2>"
  print "<div class=\"cards\">"

  print "<div class=\"c\"><h3>📓 Guestbook</h3><p>The classic first app. Sign your name, read the wall. Proves the db package over the FAT filesystem works.</p>"
  print "<span class=\"pill\">installed</span><span class=\"pill\">db</span><br><a class=\"btn\" href=\"/app/index\">Open</a></div>"

  print "<div class=\"c\"><h3>✅ TODO</h3><p>A persistent todo list served straight from the kernel's interpreter. Add, complete, repeat.</p>"
  print "<span class=\"pill\">installed</span><span class=\"pill\">db</span><br><a class=\"btn\" href=\"/app/todo\">Open</a></div>"

  print "<div class=\"c\"><h3>🌐 buildwithAJ portal</h3><p>The official AJOS.dev developer site: docs, the AJLang tour, and the kernel story. 17 pages, one script.</p>"
  print "<span class=\"pill\">installed</span><span class=\"pill\">docs</span><br><a class=\"btn\" href=\"/app/buildwithaj\">Open</a></div>"

  print "<div class=\"c\"><h3>🛍️ App Store</h3><p>This page. The catalog lives on its own AJOS server - because the store should run on the platform it sells for.</p>"
  print "<span class=\"pill\">installed</span><span class=\"pill\">you are here</span></div>"

  print "</div>"

  print "<h2>Why an app store for a hobby OS?</h2>"
  print "<p>Because \"you can build things\" only counts when people can <i>find</i> them. The store is a live demo of the whole stack: a 4MB kernel, ATA disks, the e1000 NIC driver, TCP/IP, an HTTP server, and an interpreter - serving a catalog page over the real internet.</p>"
  print "<p>Want to publish yours? <a href=\"/app/store?page=publish\" style=\"color:#67e8f9\">Read the publishing guide.</a></p>"

  print "</div>"
end

print "<div class=\"foot\">AJOS App Store · served by an i386 kernel with no userspace · <a href=\"/app/buildwithaj\" style=\"color:#22d3ee\">AJOS.dev</a></div>"
print "</body></html>"

call web_footer()
