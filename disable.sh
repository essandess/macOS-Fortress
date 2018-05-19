#!/bin/bash -x

# macOS-Fortress: Firewall, Blackhole, and Privatizing Proxy
# for Trackers, Attackers, Malware, Adware, and Spammers

# disable.sh

# commands
SUDO=/usr/bin/sudo
PORT=/usr/local/bin/port
LAUNCHCTL=/bin/launchctl
PFCTL=/sbin/pfctl
KILLALL=/usr/bin/killall
CAT=/bin/cat
ECHO=/bin/echo

$CAT <<HELPSTRING
macOS-Fortress: Firewall, Blackhole, and Privatizing Proxy
for Trackers, Attackers, Malware, Adware, and Spammers
Kernel-level, OS-level, and client-level security for macOS.

This disable script will unload all launch daemons, disable
the pf firewall, and list all insalled files WITHOUT removing them.

Disabling…
HELPSTRING

$ECHO "Unloading launchctl daemons…"

LAUNCHDAEMONS=/Library/LaunchDaemons

launchctl_unload () { if [ -f $LAUNCHDAEMONS/$PLIST ]; then $SUDO $LAUNCHCTL unload -w $LAUNCHDAEMONS/$PLIST; fi; }

for FNAME in \
	net.openbsd.pf.plist \
	net.openbsd.pf.brutexpire.plist \
	net.emergingthreats.blockips.plist \
	net.dshield.block.plist \
	net.hphosts.hosts.plist \
	com.github.essandess.easylist-pac.plist \
	com.github.essandess.adblock2privoxy.plist \
	com.github.essandess.adblock2privoxy.nginx.plist \
	org.squid-cache.squid-rotate.plist \
	; do
	launchctl_unload
done


$ECHO "Disabling pf firewall…"

$SUDO $PFCTL -d


$ECHO "Killing the squid and privoxy proxies…"

$SUDO $PORT unload squid
$SUDO $KILLALL -9 squid
$SUDO $KILLALL -9 '(squid-1)'
$SUDO $PORT unload privoxy


$ECHO ""
$ECHO "These files still exist:"

fname_exists () { if [ -f $FNAME ]; then $ECHO "$FNAME"; fi; }

PROXY_PAC_DIRECTORY=/Library/WebServer/Documents

for FNAME in \
	$PROXY_PAC_DIRECTORY/proxy.pac \
	/etc/hosts.orig \
	/etc/pf.conf.orig \
	$LAUNCHDAEMONS/net.openbsd.pf.plist \
	$LAUNCHDAEMONS/net.openbsd.pf.brutexpire.plist \
	$LAUNCHDAEMONS/net.emergingthreats.blockips.plist \
	$LAUNCHDAEMONS/net.dshield.block.plist \
	$LAUNCHDAEMONS/net.hphosts.hosts.plist \
	$LAUNCHDAEMONS/com.github.essandess.easylist-pac.plist \
	$LAUNCHDAEMONS/com.github.essandess.adblock2privoxy.plist \
	$LAUNCHDAEMONS/com.github.essandess.adblock2privoxy.nginx.plist \
	$LAUNCHDAEMONS/org.squid-cache.squid-rotate.plist \
	$HOME/Library/LaunchAgents/org.opensource.flashcookiedelete.plist \
	/usr/local/etc/blockips.conf \
	/usr/local/etc/whitelist.txt \
	/usr/local/etc/blacklist.txt \
	/usr/local/bin/macosfortress_boot_check \
	/usr/local/bin/pf_restart \
	/usr/local/bin/squid_restart \
	/usr/local/bin/privoxy_restart \
	/usr/local/bin/easylist_pac.py \
	/usr/local/bin/adblock2privoxy \
	; do
	fname_exists
done

exit 0
