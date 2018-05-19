#!/bin/bash -x
# shellcheck disable=SC2016,SC1117

# macOS Fortress: Firewall, Blackhole, and Privatizing Proxy
# for Trackers, Attackers, Malware, Adware, and Spammers

# commands
SUDO="/usr/bin/sudo"
INSTALL="/usr/bin/install"
BREW="$(command -v brew)" # homebrew can be installed anywhere.
CPAN="/usr/bin/cpan"
GPG="/usr/local/bin/gpg"
CURL="/usr/bin/curl"
# OPEN="/usr/bin/open"
DIFF="/usr/bin/diff"
PATCH="/usr/bin/patch"
LAUNCHCTL="/bin/launchctl"
APACHECTL="/usr/sbin/apachectl"
SERVERADMIN="/Applications/Server.app/Contents/ServerRoot/usr/sbin/serveradmin"
# PFCTL="/sbin/pfctl"
MKDIR="/bin/mkdir"
CAT="/bin/cat"
ECHO="/bin/echo"
MORE="/usr/bin/more"
# LSOF="/usr/sbin/lsof"
CP="/bin/cp"
RM="/bin/rm"
SH="/bin/sh"
FMT="/usr/bin/fmt"
RSYNC="/usr/bin/rsync"
# STACK="/usr/local/bin/stack"
ADBLOCK2PRIVOXY="/usr/local/bin/adblock2privoxy"

"${CAT}" <<'HELPSTRING' | "${MORE}"
macOS Fortress: Firewall, Blackhole, and Privatizing Proxy
for Trackers, Attackers, Malware, Adware, and Spammers

Kernel-level, OS-level, and client-level security for macOS. Built to
address a steady stream of attacks visible on snort and server logs,
as well as blocks ads, malicious scripts, and conceal information used
to track you around the web. After this package was installed, snort
and other detections have fallen to a fraction with a few simple
blocking actions.  This setup is a lot more capable and effective than
using a simple adblocking browser Add-On. There's a world of
difference between ad-filled web pages with and without a filtering
proxy server. It's also saved me from inadvertantly clicking on
phishing links.

This package uses these features:

	* macOS adaptive firewall
	* Adaptive firewall to brute force attacks
	* IP blocks updated about twice a day from emergingthreats.net
	  (IP blocks, compromised hosts, Malvertisers) and
	  dshield.org’s top-20
	* Host blocks updated about twice a day from hphosts.net
	* Special proxy.pac host blacklisting from hostsfile.org

This install script installs and configures an macOS Firewall and Privatizing
Proxy. It will:

	* Prompt you to install Apple's Xcode Command Line Tools and
	  Macports <https://www.macports.org/> Uses Macports to
	* Download and install several key utilities and applications
	  (wget gnupg p7zip squid privoxy nmap)
	* Configure macOS's PF native firewall (man pfctl, man pf.conf),
	  squid, and privoxy
	* Turn on macOS's native Apache webserver to serve the
	  Automatic proxy configuration http://localhost/proxy.pac
	* Networking on the local computer can be set up to use this
          Automatic Proxy Configuration without breaking App Store or
          other updates (see squid.conf)
	* Uncomment the nat directive in pf.conf if you wish to set up
          an OpenVPN server <https://discussions.apple.com/thread/5538749>
	* Install and launch daemons that download and regularly
	  update open source IP and host blacklists. The sources are
	  emergingthreats.net (net.emergingthreats.blockips.plist),
	  dshield.org (net.dshield.block.plist), hosts-file.net
	  (net.hphosts.hosts.plist), and EasyList
	  (com.github.essandess.easylist-pac.plist)
	* Installs a user launch daemon that deletes flash cookies not
          related to Adobe Flash Player settings every half-hour
          <http://goo.gl/k4BxuH>
	* After installation the connection between clients and the
	  internet looks this this:

	  Application  <--port 3128-->  Squid  <--port 8118--> Privoxy  <----> Internet

Installation:

./readme-and-install.sh

Notes:

	* Configure the squid proxy to accept connections on the LAN IP
	  and set LAN device Automatic Proxy Configurations to
	  http://lan_ip/proxy.pac to protect devices on the LAN.
	* Count the number of attacks since boot with the script
	  pf_attacks. ``Attack'' is defined as the number of blocked IPs
	  in PF's bruteforce table plus the number of denied connections
	  from blacklisted IPs in the tables compromised_ips,
	  dshield_block_ip, and emerging_threats.
	* Both squid and Privoxy are configured to forge the User-Agent.
	  The default is an iPad to allow mobile device access. Change
	  this to your local needs if necessary.
	* Whitelist or blacklist specific domain names with the files
	  /usr/local/etc/whitelist.txt and
	  /usr/local/etc/blacklist.txt. After editing these file, use
	  launchctl to unload and load the plist
	  /Library/LaunchDaemons/net.hphosts.hosts.plist, which
	  recreates the hostfile /etc/hosts-hphost and reconfigures
	  the squid proxy to use the updates.
	* Sometimes pf and privoxy do not launch at boot, in spite of
	  the use of the use of their launch daemons.  Fix this by
	  hand after boot with the scripts macosfortress_boot_check, or
	  individually using pf_restart, privoxy_restart, and
	  squid_restart. And please post a solution if you find one.
	* All open source updates are done using the 'wget -N' option
          to save everyone's bandwidth

Security:

	* These services are intended to be run on a secure LAN behind
	  a router firewall.
	* Even though the default proxy configuration will only accept
	  connections made from the local computer (localhost), do not
	  configure the router to forward ports 3128 or 8118 in case
	  you ever change this or you will be running an open web proxy.
HELPSTRING

"${ECHO}" "Installing..."

# prerequisites

# Install macOS Command Line Tools
if ! xcode-select -p &>/dev/null; then
	"${SUDO}" /usr/bin/xcode-select --install
	"${SUDO}" /usr/bin/xcodebuild -license
fi

# check for homebrew
[[ -x "${BREW}" ]] && /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

# Proxy settings in /usr/local/etc/macports/macports.conf
"${BREW}" update && "${BREW}" outdated && "${BREW}" upgrade && "${BREW}" cleanup

# Install wget, gnupg, 7z, pcre, proxies, perl, and python modules

# we don't need to do this with homebrew, since squid would be updated if it were extant above
# command -v squid &>/dev/null && "${BREW}" uninstall squid && "${BREW}" cleanup
"${BREW}" install wget gnupg p7zip pcre squid privoxy nginx nmap python3 haskell-stack
"${PIP3}" install scikit-learn matplotlib numpy
"${SUDO}" "${CPAN}" install
"${SUDO}" "${CPAN}" -i Data::Validate::IP
"${SUDO}" "${CPAN}" -i Data::Validate::Domain
# Used to verify downloads
"${SUDO}" "${CURL}" -O https://secure.dshield.org/PGPKEYS.txt
"${SUDO}" "${GPG}" --homedir /var/root/.gnupg --import PGPKEYS.txt
"${SUDO}" "${GPG}" --homedir /var/root/.gnupg --recv-keys C1E94509 608D9001
"${SUDO}" "${GPG}" --homedir /var/root/.gnupg --list-keys
"${CAT}" <<'GPGID'
Keep your gpg keychain up to date by checking the keys IDs with these commands:

/usr/local/bin/gpg --verify /usr/local/etc/block.txt.asc /usr/local/etc/block.txt
/usr/bin/unzip -o /usr/local/etc/hosts.zip -d /tmp/hphosts && /usr/local/bin/gpg --verify /tmp/hphosts/hosts.txt.asc /tmp/hphosts/hosts.txt
GPGID
"${ECHO}" 'To delete expited keys, see http://superuser.com/questions/594116/clean-up-my-gnupg-keyring/594220#comment730593_594220'
"${ECHO}" 'These commands delete expired GPG keys:'
"${CAT}" <<DELETE_EXPIRED_GPG_KEYS
"${SUDO}" "${GPG}" --homedir /var/root/.gnupg --list-keys | "${AWK}" '/^pub.* \[expired\: / {id="${2}"; sub(/^.*\//, "", id); print id}' | "${FMT}" -w 999 | "${SED}" 's/^/gpg --delete-keys /;'
"${SUDO}" "${GPG}" --homedir /var/root/.gnupg --delete-keys KeyIDs ...
DELETE_EXPIRED_GPG_KEYS

# apache for proxy.pac
if ! [ -d /Applications/Server.app ]; then
	# macOS native apache server for proxy.pac
	PROXY_PAC_DIRECTORY="/Library/WebServer/Documents"
	"${SUDO}" "${APACHECTL}" start
else
	# macOS Server for proxy.pac
	PROXY_PAC_DIRECTORY="/Library/Server/Web/Data/Sites/proxy.mydomainname.private"
	if [ -d "${PROXY_PAC_DIRECTORY}" ]; then
		"${CAT}" <<PROXY_PAC_DNS
Please use Server.app's DNS and Websites services to create the hostname and website
${PROXY_PAC_DIRECTORY##*/}, edit the configuration files

	$(/usr/bin/grep -F -l mydomain ./* | tr '\n' ' ')

to reflect this name, then run this script again.
PROXY_PAC_DNS
		exit 1
	fi
	"${SUDO}" "${SERVERADMIN}" stop web
	"${SUDO}" "${SERVERADMIN}" start web
fi
"${SUDO}" "${INSTALL}" -m 644 ./proxy.pac "${PROXY_PAC_DIRECTORY}"
"${SUDO}" "${INSTALL}" -m 644 ./proxy.pac "${PROXY_PAC_DIRECTORY}"/proxy.pac.orig

# Compile and install adblock2privoxy
if ! [ -x "${ADBLOCK2PRIVOXY}" ]; then
	"${SUDO}" "${MKDIR}" -p /usr/local/etc/adblock2privoxy
	"${SUDO}" "${MKDIR}" -p /usr/local/etc/adblock2privoxy/css
	"${SUDO}" "${RSYNC}" -a easylist-pac-privoxy/adblock2privoxy/adblock2privoxy* /usr/local/etc/adblock2privoxy
	# ensure that macOS /usr/bin/gcc is the C compiler
	"${SUDO}" -E "${SH}" -c 'export PATH=/usr/bin:"${PATH}" ; export STACK_ROOT=/usr/local/etc/.stack ; ( cd /usr/local/etc/adblock2privoxy/adblock2privoxy ; /usr/local/bin/stack setup --allow-different-user ; /usr/local/bin/stack install --local-bin-path /usr/local/bin --allow-different-user )'
	"${SUDO}" "${INSTALL}" -m 644 ./easylist-pac-privoxy/adblock2privoxy/nginx.conf /usr/local/etc/adblock2privoxy
	"${SUDO}" "${INSTALL}" -m 644 ./easylist-pac-privoxy/adblock2privoxy/default.html /usr/local/etc/adblock2privoxy/css
fi

# proxy configuration

# squid

#squid.conf
"${SUDO}" "${INSTALL}" -m 644 -B .orig /usr/local/etc/squid/squid.conf.default /usr/local/etc/squid/squid.conf
"${SUDO}" "${INSTALL}" -m 644 -B .orig /usr/local/etc/squid/squid.conf.default /usr/local/etc/squid/squid.conf.orig
"${DIFF}" -NaurdwB -I '^ *#.*' /usr/local/etc/squid/squid.conf ./squid.conf >/tmp/squid.conf.patch
"${SUDO}" "${PATCH}" -p5 /usr/local/etc/squid/squid.conf </tmp/squid.conf.patch
"${RM}" /tmp/squid.conf.patch

# rotate squid logs
"${SUDO}" "${INSTALL}" -m 644 ./org.squid-cache.squid-rotate.plist /Library/LaunchDaemons
if ! [ -d /usr/local/var/squid/logs ]; then
	"${SUDO}" "${MKDIR}" -p -m 644 /usr/local/var/squid/logs
	"${SUDO}" "${CHOWN}" -R squid:squid /usr/local/var/squid
fi

# privoxy

#config
"${SUDO}" "${INSTALL}" -m 640 /usr/local/etc/privoxy/config /usr/local/etc/privoxy/config.orig
"${DIFF}" -NaurdwB -I '^ *#.*' /usr/local/etc/privoxy/config ./config >/tmp/config.patch
"${SUDO}" "${PATCH}" -p5 /usr/local/etc/privoxy/config </tmp/config.patch
"${RM}" /tmp/config.patch

#match-all.action
"${SUDO}" "${INSTALL}" -m 640 -B .orig /usr/local/etc/privoxy/match-all.action /usr/local/etc/privoxy/match-all.action.orig
"${DIFF}" -NaurdwB -I '^ *#.*' /usr/local/etc/privoxy/match-all.action ./match-all.action >/tmp/match-all.action.patch
"${SUDO}" "${PATCH}" -p5 /usr/local/etc/privoxy/match-all.action </tmp/match-all.action.patch
"${RM}" /tmp/match-all.action.patch

#user.action
"${SUDO}" "${INSTALL}" -m 644 -B .orig /usr/local/etc/privoxy/user.action /usr/local/etc/privoxy/user.action.orig
"${DIFF}" -NaurdwB -I '^ *#.*' /usr/local/etc/privoxy/user.action ./user.action >/tmp/user.action.patch
"${SUDO}" "${PATCH}" -p5 /usr/local/etc/privoxy/user.action </tmp/user.action.patch
"${RM}" /tmp/user.action.patch

"${SUDO}" "${BASH}" -c '( cd /usr/local/etc/privoxy ; /usr/sbin/chown privoxy:privoxy config* *.action *.filter )'

#privoxy logs
if ! [ -d /usr/local/var/log/privoxy ]; then
	"${SUDO}" "${MKDIR}" -m 644 /usr/local/var/log/privoxy
	"${SUDO}" "${CHOWN}" privoxy:privoxy /usr/local/var/log/privoxy
fi

# install the files
"${SUDO}" "${CP}" /etc/hosts /etc/hosts.orig
"${SUDO}" "${INSTALL}" -b -B .orig ./pf.conf /etc
"${SUDO}" "${INSTALL}" -m 644 ./net.openbsd.pf.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./net.openbsd.pf.brutexpire.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./net.emergingthreats.blockips.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./net.dshield.block.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./net.hphosts.hosts.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./com.github.essandess.easylist-pac.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./easylist-pac-privoxy/adblock2privoxy/com.github.essandess.adblock2privoxy.plist /Library/LaunchDaemons
"${SUDO}" "${INSTALL}" -m 644 ./easylist-pac-privoxy/adblock2privoxy/com.github.essandess.adblock2privoxy.nginx.plist /Library/LaunchDaemons
"${INSTALL}" -m 644 ./org.opensource.flashcookiedelete.plist ~/Library/LaunchAgents
"${SUDO}" "${MKDIR}" -p /usr/local/etc
"${SUDO}" "${INSTALL}" -m 644 ./blockips.conf /usr/local/etc
"${SUDO}" "${INSTALL}" -m 644 ./whitelist.txt /usr/local/etc
"${SUDO}" "${INSTALL}" -m 644 ./blacklist.txt /usr/local/etc

"${SUDO}" "${INSTALL}" -m 755 ./pf_attacks /usr/local/bin
"${SUDO}" "${INSTALL}" -m 755 ./macosfortress_boot_check /usr/local/bin
"${SUDO}" "${INSTALL}" -m 755 ./pf_restart /usr/local/bin
"${SUDO}" "${INSTALL}" -m 755 ./squid_restart /usr/local/bin
"${SUDO}" "${INSTALL}" -m 755 ./privoxy_restart /usr/local/bin
"${SUDO}" "${INSTALL}" -m 755 ./easylist-pac-privoxy/easylist_pac.py /usr/local/bin

# daemons
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/net.openbsd.pf.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/net.openbsd.pf.brutexpire.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/net.emergingthreats.blockips.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/net.dshield.block.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/net.hphosts.hosts.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/com.github.essandess.easylist-pac.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist
"${SUDO}" "${LAUNCHCTL}" load -w /Library/LaunchDaemons/org.squid-cache.squid-rotate.plist

"${LAUNCHCTL}" load ~/Library/LaunchAgents/org.opensource.flashcookiedelete.plist

"${SUDO}" "${BREW}" services start squid
"${SUDO}" "${BREW}" services start privoxy

# Turn on macOS Server's adaptive firewall:
if [ -d /Applications/Server.app ]; then
	"${SUDO}" /Applications/Server.app/Contents/ServerRoot/usr/sbin/serverctl enable service=com.apple.afctl
	"${SUDO}" /Applications/Server.app/Contents/ServerRoot/usr/libexec/afctl -f
fi

# check after boot
# /usr/local/bin/macosfortress_boot_check

exit 0
