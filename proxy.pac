function FindProxyForURL(url, host)
{
if (
// Bypass proxy on the LAN for local DNS domainname
//   (host == "mydomainname.com") ||
//   dnsDomainIs(host, ".mydomainname.com") ||
//   (host == "mydomainname.private") ||
//   dnsDomainIs(host, ".mydomainname.private") ||
//   isPlainHostName(host) ||
   shExpMatch(host, "10.*") ||
   shExpMatch(host, "172.16.*") ||
   shExpMatch(host, "192.168.*") ||
   shExpMatch(host, "127.*") ||
   dnsDomainIs(host, ".LOCAL") ||
//   (dnsDomainIs(host, ".local")  &&
//        !dnsDomainIs(host, ".mydomainname.com")) ||
   (url.substring(0,3) == "ftp") ||
   // TV Guide listings on EyeTV; TitanTV Remote Scheduling
   (host == "epg.eyetv.com") ||
   (host == "xmlrpc.macrovision.com") ||
   (host == "partners.titantv.com") ||
   dnsDomainIs(host, ".apple.com") ||
   (url.substring(0,5) != "http:")
)
        return "DIRECT";
else
// Use the listen address for squid
//        return "PROXY mydomainname.com:3128";
        return "PROXY 127.0.0.1:3128";
}
