// hotspot.aj - a captive-portal style landing page (App Store app)
// Route: /app/hotspot  (GET splash, POST "connects" the client)

import "web"

let hs__connected = 0
let hs__who = web_esc(web_form("who"))

if web_method() == "POST" then
  if str_len(hs__who) > 0 then
    let hs__connected = 1
  else
    print "<div class=\"card\"><p class=\"err\">Enter a name to connect.</p>"
    print "<p><a href=\"/app/hotspot\">Try again</a></p></div>"
  end
end

if hs__connected == 1 then
  print "<div class=\"card\">"
  print "<h2 style=\"color:#22d3ee;margin-top:0\">Welcome, " + hs__who + "!</h2>"
  print "<p>You are now connected to the <b>AJOS Hotspot</b>. Your session is authenticated by a 4MB kernel with no userspace.</p>"
  print "<p style=\"color:#94a3b8;font-size:13px\">Session limits: none. Uptime: since boot. Support: the guestbook.</p>"
  print "<p><a class=\"btn\" href=\"/app/index\">Guestbook</a> <a class=\"btn\" href=\"/app/store\">App Store</a></p>"
  print "</div>"
else
  if hs__connected == 0 then
    if str_len(hs__who) == 0 then
      if web_method() == "GET" then
        print "<div class=\"card\">"
        print "<h2 style=\"margin-top:0\">Free Wi-Fi</h2>"
        print "<p style=\"color:#94a3b8\">You are connecting through an AJOS hotspot. Accept the terms and pick a display name.</p>"
        print "<form method=\"POST\" action=\"/app/hotspot\">"
        print "<input name=\"who\" placeholder=\"Your name\" maxlength=\"32\">"
        print "<p><label style=\"font-size:13px;color:#94a3b8\"><input type=\"checkbox\" name=\"agree\" value=\"yes\" checked> I promise not to mine crypto on this router</label></p>"
        print "<button type=\"submit\">Connect</button>"
        print "</form></div>"
      end
    end
  end
end

print "<p style=\"color:#64748b;font-size:12.5px\">Install me on your own AJOS server: <code>appinstall 203.191.130.131 hotspot</code></p>"

call web_footer()
