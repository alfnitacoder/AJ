// dnscheck.aj - resolve a domain A record via AJLang dns()
print "=== AJLang DNS Checker ==="

def check_dns(domain)
  print "Looking up..."
  let ip = dns(domain)
  if ip == "" then
    print "FAILED: timeout or no A record"
  else
    print "OK:"
    print ip
  end
end

let target = "example.com"
print target
check_dns(target)
print "Done."
