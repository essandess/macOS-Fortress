macOS-Fortress
===========

# macOS-Fortress: Firewall, Blackhole, and Privatizing Proxy for Trackers, Attackers, Malware, Adware, and Spammers; with On-Demand and On-Access Anti-Virus Scanning

Kernel-level, OS-level, and client-level security for macOS. Built to address a steady stream of attacks visible on snort and server logs, as well as blocks ads, malicious scripts, and conceal information used to track you around the web. After this package was installed, snort and other detections have fallen to a fraction with a few simple blocking actions.  This setup is a lot more capable and effective than using a simple adblocking browser add-on. There's a world of difference between ad-filled web pages with and without a filtering proxy server. It's also saved me from inadvertantly clicking on phishing links.

## Proxy features
* macOS adaptive firewall
* Adaptive firewall to brute force attacks
* IP blocks updated about twice a day from emergingthreats.net (IP blocks, compromised hosts, Malvertisers) and [dshield.org](https://secure.dshield.org)’s top-20
* Host blocks updated about twice a day from [hphosts.net](https://www.hosts-file.net)
* [EasyList](https://easylist.to/index.html) Tracker and Adblock Rules to Proxy Auto Configuration (PAC) [proxy.pac](https://raw.githubusercontent.com/essandess/easylist-pac-privoxy/master/proxy.pac) file and [Privoxy](http://www.privoxy.org) Actions and Filters
* Uses [easylist-pac-privoxy](../../../easylist-pac-privoxy) and [adblock2privoxy](../../../adblock2privoxy) to easily incorporate multiple blocking rulesets into both PAC and Privoxy formats, including [easyprivacy.txt](https://easylist.to/easylist/easyprivacy.txt), [easylist.txt](https://easylist.to/easylist/easylist.txt), [fanboy-annoyance.txt](https://easylist.to/easylist/fanboy-annoyance.txt), [fanboy-social.txt](https://easylist.to/easylist/fanboy-social.txt), [antiadblockfilters.txt](https://easylist-downloads.adblockplus.org/antiadblockfilters.txt), [malwaredomains_full.txt](https://easylist-downloads.adblockplus.org/malwaredomains_full.txt), and the anti-spamware list [adblock-list.txt](https://raw.githubusercontent.com/Dawsey21/Lists/master/adblock-list.txt).

## Anti-Virus features
* Configures [clamAV](http://www.clamav.net) for macOS with regular on-demand scans and on-access scanning of user `Downloads` 
and `Desktop` directories.
* See the [MacPorts](https://www.macports.org/) port `clamav-server` for details, `port notes clamav-server`.

## Installation

```bash
sudo port install macos-fortress
port notes macos-fortress
sudo port load macos-fortress
```

After initial installation, it is necessary to kickstart these launch daemons, which run on a schedule, and do not run at load time:

```bash
sudo launchctl kickstart -k system/org.macports.macos-fortress-dshield
sudo launchctl kickstart -k system/org.macports.macos-fortress-emergingthreats
sudo launchctl kickstart -k system/org.macports.macos-fortress-hphosts
sudo launchctl kickstart -k system/org.macports.adblock2privoxy
sudo launchctl kickstart -k system/org.macports.macos-fortress-easylistpac
```

The default web server is native macOS Apache, which must be started with the command:
```bash
sudo apachectl start
```

Note that all files in this repo are superceded by the MacPorts port
[macos-fortress](https://github.com/macports/macports-ports/tree/master/net/macos-fortress), including the
deprecated installation script [readme-and-install.sh](./readme-and-install.sh).

### Firewall-only installation

```bash
sudo port install macos-fortress-pf
port notes macos-fortress-pf
sudo port load macos-fortress-pf
```

### Proxy-only installation

```bash
sudo port install macos-fortress-proxy
port notes macos-fortress-proxy
sudo port load macos-fortress-proxy
```

## Check and troubleshoot setup

> `sudo sh macosfortress_setup_check.sh`

Working output:
```
Checking macOS-Fortress installed items (run as sudo)…

Checking launchd.plist files…
[✅] /Library/LaunchDaemons/net.openbsd.pf.plist exists
[✅] /Library/LaunchDaemons/net.openbsd.pf.brutexpire.plist exists
[✅] /Library/LaunchDaemons/net.emergingthreats.blockips.plist exists
[✅] /Library/LaunchDaemons/net.dshield.block.plist exists
[✅] /Library/LaunchDaemons/net.hphosts.hosts.plist exists
[✅] /Library/LaunchDaemons/com.github.essandess.easylist-pac.plist exists
[✅] /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.plist exists
[✅] /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist exists
[✅] /Library/LaunchDaemons/org.squid-cache.squid-rotate.plist exists
[✅] /Library/LaunchDaemons/org.macports.Squid.plist exists
[✅] /Library/LaunchDaemons/org.macports.Privoxy.plist exists
[✅] /Library/LaunchDaemons/org.macports.clamd.plist exists
[✅] /Library/LaunchDaemons/org.macports.freshclam.plist exists
[✅] /Library/LaunchDaemons/org.macports.ClamavScanSchedule.plist exists
[✅] /Library/LaunchDaemons/org.macports.ClamavScanOnAccess.plist exists

Checking launchd.plist's. These should all be installed with return
code 0 (2d column of `sudo launchctl list`)…
[✅]	-	0	com.github.essandess.easylist-pac
[✅]	-	0	net.dshield.block
[✅]	-	0	org.squid-cache.squid-rotate
[✅]	91695	0	org.macports.ClamdScanOnAccess
[✅]	-	0	org.macports.freshclam
[✅]	-	0	net.openbsd.pf
[✅]	-	0	com.github.essandess.adblock2privoxy
[✅]	35403	0	org.macports.clamd
[✅]	-	0	org.macports.ClamavScanSchedule
[✅]	-	0	net.openbsd.pf.brutexpire
[✅]	-	0	net.emergingthreats.blockips
[✅]	37069	0	org.macports.Squid
[✅]	36183	0	org.macports.Privoxy
[✅]	5578	0	com.github.essandess.adblock2privoxy.nginx
[✅]	-	0	net.hphosts.hosts

Checking PF files…
[✅] /etc/pf.conf exists
[✅] /usr/local/etc/blockips.conf exists
[✅] /usr/local/etc/emerging-Block-IPs.txt exists
[✅] /usr/local/etc/compromised-ips.txt exists
[✅] /usr/local/etc/dshield_block_ip.txt exists
[✅] /usr/local/etc/block.txt exists
[✅] /usr/local/etc/block.txt.asc exists

Checking PF…
[✅] PF is enabled and running

Checking hphosts files…
[✅] /etc/hosts-hphosts exists
[✅] /usr/local/etc/hosts.zip exists
[✅] /usr/local/etc/hphosts-partial.asp exists
[✅] /usr/local/etc/whitelist.txt exists
[✅] /usr/local/etc/blacklist.txt exists

Checking /etc/hosts-hphosts creation…
[✅] /etc/hosts-hphosts exists

Checking proxy PAC and proxy chain files…
[✅] /Library/WebServer/Documents/proxy.pac.orig exists
[✅] /Library/WebServer/Documents/proxy.pac exists
[✅] /usr/local/bin/easylist_pac.py exists
[✅] /usr/local/bin/adblock2privoxy exists
[✅] /usr/local/etc/proxy.pac exists
[✅] /usr/local/etc/adblock2privoxy/nginx.conf exists
[✅] /usr/local/etc/adblock2privoxy/css/default.html exists
[✅] /usr/local/etc/adblock2privoxy/privoxy/ab2p.action exists
[✅] /usr/local/etc/adblock2privoxy/privoxy/ab2p.filter exists
[✅] /usr/local/etc/adblock2privoxy/privoxy/ab2p.system.action exists
[✅] /usr/local/etc/adblock2privoxy/privoxy/ab2p.system.filter exists
[✅] /opt/local/etc/squid/squid.conf exists
[✅] /opt/local/var/squid/logs/cache.log exists
[✅] /opt/local/etc/privoxy/config exists
[✅] /opt/local/var/log/privoxy/logfile exists

Checking proxy status…
[✅] Squid is running properly
[✅] Privoxy is running properly
[✅] Privoxy config http://p.p/ via http://localhost:3128 is running properly
[✅] nginx is running properly
[✅] PAC /Library/WebServer/Documents/proxy.pac.orig passes Javascript parsing
[✅] PAC /Library/WebServer/Documents/proxy.pac passes Javascript parsing
[✅] Web server for http://localhost/proxy.pac is running properly
[✅] Blackhole server for http://localhost:8119/ is running properly
```

## Disabling

```
sudo port unload macos-fortress
```

or

```
sudo port uninstall macos-fortress
```

This repo is superceded by the MacPorts port
[macos-fortress](https://github.com/macports/macports-ports/tree/master/net/macos-fortress), including the
deprecated disable/uninstall script [disable.sh](./disable.sh), which was originally used to unload all launch daemons, 
disable the pf firewall, and list all installed files **without** removing them.

## Configuration modifications

There are three major, independent, and configurable components to the repo: the PF firewall, the proxy chain, and the
AV scanner. Here are a few configuration pointers.

### PF firewall

The file [pf.conf](./pf.conf) controls the firewall ruleset and likely must be edited on a specific computer and network, or 
edited for a VPN server [configuration](../../../macos-openvpn-server/pf.conf).

* The PF firewall can be disabled with the command:
> `sudo pfctl -d`
* The variable `int_if` for the internal interface is set to `en0`. This should be changed to the active interface on your 
computer, which can be determined with the command `ifconfig -a`, or more specificall:
> `ifconfig | pcregrep -M -o '^[^\t:]+:([^\n]|\n\t)*status: active' | egrep -o -m 1 '^[^\t:]+'`
* The table `<lan_inet>` is set to the standard reserved ranges `{ 10/8, 172.16/12, 192.168/16 }`. This must be changed
to the CIDR ranges on the specific LAN.
* Specific services accessible only on the LAN and on the open internet should be selected and set in the appropriate 
variables. See `/etc/services`.
* The PF firewall ruleset can be flushed, enabled, and reintialized with the command:
> `sudo pfctl -Fall && sudo pfctl -ef /etc/pf.conf`
* See the `pfctl` commands in the script [pf_attacks](./pf_attacks) to determine IP addresses and counts for the various 
blocked IPs. E.g., the adaptive table `<bruteforce>` is shown using the command:
> `sudo pfctl -t bruteforce -Ts`

### Proxy chain

There are four components to the proxy chain: a Proxy AutocConfiguration (PAC) file
[proxy.pac](../../../easylist-pac-privoxy/proxy.pac), a caching `squid` proxy, a non-caching `privoxy` proxy, and an auxiliary  
`nginx` webserver. The PAC file [proxy.pac](../../../easylist-pac-privoxy/proxy.pac) proxies unblocked web requests to squid 
on port 3128, and blocked requests to a static nginx page on port 8119. PAC file blocking rules are derived from Easylist 
rules. The squid proxy is configured in [squid.conf](./squid.conf) to use privoxy as a parent proxy on port 8118. Privoxy is 
configured in [config](./config) to sent web requests to the internet, and use the auxiliary nginx webserver for CSS-based 
element hiding on port 8119. Privoxy `.action` and `.filter` files, and nginx `.css` files are created from Easylist rules 
using the repo [adblock2privoxy](../../../adblock2privoxy).

Each of these proxy configurations will work, with [varying](../../../easylist-pac-privoxy#purpose) blocking capabilities:
* http://localhost/proxy.pac (PAC file, squid, privoxy, nginx element hiding)
* http://localhost:3128 (squid, privoxy, nginx element hiding)
* http://localhost:8118 (privoxy, nginx element hiding)

Browsing to the privoxy configuration page http://p.p/ through any of these proxy configurations is a check on whether the 
proxy is running and configured correctly.

To provide these services on a firewalled LAN, edit the squid, privoxy, and nginx configuration files
[squid.conf](./squid.conf), [config](./config), and [nginx.conf](../../../adblock2privoxy//nginx.conf) so that they're 
available for devices on the LAN, or connecting from a [VPN tunnel](../../../macos-openvpn-server/).

### Macports updates

Update Macports packages regularly. This command with update the Macports database, update all installed packages, and uninstall all older, inactive versions.

`sudo bash -c 'port selfupdate ; port -puN upgrade outdated ; port uninstall inactive'`

### Warning about Privoxy compression

Though it's possible to build Privoxy with the `configure` `--enable-compression` option, 
compressed HTTP traffic within a [VPN tunnel](../../../macos-openvpn-server) exposes your traffic to the
CRIME/BEAST/[VORACLE](https://openvpn.net/security-advisory/the-voracle-attack-vulnerability/) attacks and is generally not 
recommended.

### Browser Path stripping/inclusion in `FindProxyForURL`

Many Easylist rules use URL path information to determine of the request should be blocked or not. Becasue the full URL with 
its path is necessarily visible to the browser, this information can be passed to the Proxy Autoconfig file, even if the URL 
uses HTTPS, which is an advantage of using a PAC file for filtering.

However, this behavior presents a security vulnerability if the OS is configured to use a malicious PAC file. This issue can 
affect any browser, including [Chrome](https://bugs.chromium.org/p/chromium/issues/detail?id=593759) and
[Safari](https://blog.checkpoint.com/2017/04/27/osx-malware-catching-wants-read-https-traffic/).

Recent versions of Chrome and Firefox are configured to only send the domain name to the `FindProxyForURL` function, which 
closes this potential security vulnerability, but also prevents blocks based on URL path information.

To allow this blocking capability:
* **Chrome**: Set the policy `PacHttpsUrlStrippingEnabled` to be `false`. In macOS:
> `defaults write com.google.Chrome PacHttpsUrlStrippingEnabled -bool false`
* **Firefox**: Set the configuration variable `network.proxy.autoconfig_url.include_path` to be `true` using the Firefox link [about:config](about:config).

## Installation details
The MacPorts port
[macos-fortress](https://github.com/macports/macports-ports/tree/master/net/macos-fortress)
(`sudo port install macos-fortress`) installs and configures an macOS Firewall and Privatizing
Proxy. It will:
* Uses Macports to download and install several key utilities and applications (wget gnupg p7zip squid privoxy nmap)
* Configure macOS's PF native firewall (man pfctl, man pf.conf), squid, and privoxy
* Networking on the local computer can be set up to use this Automatic Proxy Configuration without breaking App Store or other updates (see squid.conf)
* Uncomment the nat directive in pf.conf if you wish to set up an [OpenVPN server](../../../macos-openvpn-server)
* Install and launch daemons that download and regularly update open source IP and host blacklists. The sources are  emergingthreats.net (net.emergingthreats.blockips.plist), dshield.org (net.dshield.block.plist), hosts-file.net (net.hphosts.hosts.plist), and [EasyList](https://easylist.to) (com.github.essandess.easylist-pac.plist, com.github.essandess.adblock2privoxy.plist)
* After installation the connection between clients and the internet looks this this:

> **Application** :arrow_right: **`proxy.pac`** :arrow_right:port 3128:arrow_right: **Squid** :arrow_right:port 8118:arrow_right: **Privoxy**  :arrow_right: **Internet**

An auxilliary nginx-based webserver (nominally on `localhost:8119`) is used for both a `proxy.pac` ad and tracker blackhole and for CSS element blocking rules with the Privoxy configuration generated by [adblock2privoxy](../../../adblock2privoxy).

## Public Service Announcement 

This firewall is configured to block all known tracker and adware content—in the browser, in-app, wherever it finds them. Many websites now offer an additional way to block ads: subscribe to their content. Security and privacy will always necessitate ad blocking, but now that this software has become mainstream with mainstream effects, ad blocker users must consider the [potential impact](http://arstechnica.com/business/2010/03/why-ad-blocking-is-devastating-to-the-sites-you-love/) of ad blocking on the writers and publications that are important to them. Personally, two publications that I gladly pay for, especially for their important 2016 US Presidential election coverage, are the *[New York Times](http://www.nytimes.com)* and *[The Atlantic](http://www.theatlantic.com)*. I encourage all users to subscribe to their own preferred publications and writers.


## Tracker blocking

[Lightbeam](https://www.mozilla.org/en-US/lightbeam/), the tracking tracker Firefox add-on, shows how ad- and tracker-blocking works to prevent third parties monitoring you or your children's online activities. My daughter enjoys the learning exercises at the children's website [ABCya!](http://www.abcya.com). The Lightbeam graph below on the left shows all the third party trackers after less than a minute of browser activity, without using a privatizing proxy. The graph on the right shows all this tracker activity blocked when this privatizing proxy is used.


![Lightbeam graph without proxy](Lightbeam_noproxy.png)| ![Lightbeam graph without proxy](Lightbeam_proxy.png)
------------ | -------------
Lightbeam graph without proxy | Lightbeam graph with proxy

This problem is the subject of Gary Kovacs's TED talk, *Tracking Our Online Trackers:*

[![Tracking our online trackers](https://www.wired.com/images_blogs/business/2012/02/6792752454_99d91d2a92_z.jpg)](https://www.youtube.com/watch?v=f_f5wNw-2c0 "Tracking our online trackers")


## Attack blocking

The snort intrusion detection system reports far fewer events when known attack sites are blackholed by the packet filter:

![snort+BASE Overview](BASE_Overview.PNG)| ![snort+BASE Events](BASE_Events.PNG)
------------ | -------------
snort+BASE Overview | snort+BASE Events

## Notes

* Configure the squid proxy to accept connections on the LAN IP and set LAN device Automatic Proxy Configurations to http://lan_ip/proxy.pac to protect devices on the LAN.
* Count the number of attacks since boot with the script pf_attacks. ``Attack'' is defined as the number of blocked IPs in PF's bruteforce table plus the number of denied connections from blacklisted IPs in the tables compromised_ips, dshield_block_ip, and emerging_threats.
* Both squid and Privoxy are configured to forge the User-Agent. The default is an iPad to allow mobile device access. Change this to your local needs if necessary.
* Whitelist or blacklist specific domain names with the files `/usr/local/etc/whitelist.txt` and `/usr/local/etc/blacklist.txt`. After editing these file, use launchctl to unload and load the plist `/Library/LaunchDaemons/net.hphosts.hosts.plist`, which recreates the hostfile `/etc/hosts-hphost` and reconfigures the squid proxy to use the updates.
* Sometimes pf and privoxy do not launch at boot, in spite of the use of the use of their launch daemons.  Fix this by hand after boot with the scripts `macosfortress_boot_check`, or individually using `pf_restart`, `privoxy_restart`, and `squid_restart`. And please post a solution if you find one.
* All open source updates are done using the `wget -N` option to save everyone's bandwidth

## Security

* These services are intended to be run on a secure LAN behind a router firewall.
* The default proxy configuration will only accept connections made from the local computer (localhost). If you change this to accept connections from any client on your LAN, do not configure the router to forward ports 3128 or 8118, or you will be running an open web proxy.
