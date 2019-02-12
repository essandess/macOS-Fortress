#!/bin/bash -x

# macOS-Fortress: Firewall, Blackhole, and Privatizing Proxy
# for Trackers, Attackers, Malware, Adware, and Spammers

# macos_fortress_setup_check.sh

# commands

SUDO=/usr/bin/sudo
PORT=/opt/local/bin/port
LAUNCHCTL=/bin/launchctl
PFCTL=/sbin/pfctl
KILLALL=/usr/bin/killall
CAT=/bin/cat
SED=/usr/bin/sed
GREP=/usr/bin/grep
EGREP=/usr/bin/egrep
ECHO=/bin/echo
PFCTL=/sbin/pfctl
HEAD=/usr/bin/head
TAIL=/usr/bin/tail
LSOF=/usr/sbin/lsof
KILLALL=/usr/bin/killall
PS=/bin/ps
WC=/usr/bin/wc
CURL=/usr/bin/curl
AWK=/usr/bin/awk
HOSTNAME=/bin/hostname

PROXY_PAC_SERVER=localhost
PROXY_SERVER=localhost
LAUNCHDAEMONS=/Library/LaunchDaemons
# apache for proxy.pac
if ! [ -d /Applications/Server.app ]
then
    # macOS native apache server for proxy.pac
    PROXY_PAC_DIRECTORY=/Library/WebServer/Documents
else
    # macOS Server for proxy.pac
    PROXY_PAC_DIRECTORY="/Library/Server/Web/Data/Sites/$(HOSTNAME)"
fi

fname_exists () { [ -f $FNAME ] && echo "[✅] ${FNAME} exists" || echo "[❌] ${FNAME} DOESN'T EXIST!"; }

# print launchd status, or echo "# comment line"
launchctl_check () { $EGREP -q -e '^(\d+|-)+\s[0]' <<< ${LINE} && echo "[✅]\t${LINE}" || echo "[❌]\t${LINE}"; }

# launchctl_check () { [ "${PLIST##\#*}" == "" ] && echo "${PLIST}" || ( [ -f $LAUNCHDAEMONS/$PLIST ] && ( LINE=`$SUDO $LAUNCHCTL list | $EGREP -e $(echo $PLIST | $SED -e 's/.plist$//')'$'`; $EGREP -q -e '^(\d+|-)+\s[0]' <<< $LINE && echo "[✅] ${LINE}" || "[❌] ${LINE}" ) || echo "[❌] $LAUNCHDAEMONS/$PLIST: NOT INSTALLED!"; ) }

$CAT <<HELPSTRING
Checking macOS-Fortress installed items (run as sudo)…
HELPSTRING

# launchcd.plist
$CAT <<EOF

Checking launchd.plist files…
EOF

LAUNCHD_PLISTS=( \
	net.openbsd.pf.plist \
	net.openbsd.pf.brutexpire.plist \
	net.emergingthreats.blockips.plist \
	net.dshield.block.plist \
	net.hphosts.hosts.plist \
	com.github.essandess.easylist-pac.plist \
	com.github.essandess.adblock2privoxy.plist \
	com.github.essandess.adblock2privoxy.nginx.plist \
	org.squid-cache.squid-rotate.plist \
        org.macports.Squid.plist \
        org.macports.Privoxy.plist \
        org.macports.clamd.plist \
        org.macports.freshclam.plist \
        org.macports.clamdscan.plist \
        org.macports.ClamdScanOnAccess.plist \
    )

for PLIST in "${LAUNCHD_PLISTS[@]}" \
	; do \
	FNAME="${LAUNCHDAEMONS}/${PLIST}"; \
	fname_exists; \
done

$CAT <<'EOF'

Checking launchd.plist's. These should all be installed with return
code 0 (2d column of `sudo launchctl list`)…
EOF

IFS="|"
LAUNCHD_PLISTS_REGEX="(${LAUNCHD_PLISTS[*]%%.plist})"
IFS=$'\n'
LAUNCHD_LIST=(`$SUDO $LAUNCHCTL list | $EGREP "${LAUNCHD_PLISTS_REGEX}"`)

# loaded launchcd.plist's
for LINE in "${LAUNCHD_LIST[@]}" \
	; do \
	launchctl_check; \
done
# unloaded launchcd.plist's
LAUNCHD_SERVICES=(`for L in "${LAUNCHD_LIST[@]}"; do $AWK '{ print $3 }' <<< "${L}"; done`)
IFS="|"
LAUNCHD_SERVICES_REGEX="(${LAUNCHD_SERVICES[*]})"
IFS=$'\n'
for SERVICE in "${LAUNCHD_PLISTS[@]}" \
	; do \
	$EGREP -q -e "${LAUNCHD_SERVICES_REGEX}" <<< "${SERVICE%%.plist}" \
	|| echo "[❌] ${SERVICE%%.plist} isn't loaded!"; \
done

# PF
$CAT <<EOF

Checking PF files…
EOF

unset IFS
PF_FILES=( \
	/etc/pf.conf \
	/usr/local/etc/blockips.conf \
        /usr/local/etc/emerging-Block-IPs.txt \
        /usr/local/etc/compromised-ips.txt \
        /usr/local/etc/dshield_block_ip.txt \
	/usr/local/etc/block.txt \
	/usr/local/etc/block.txt.asc \
)

for FNAME in "${PF_FILES[@]}" \
	; do \
	fname_exists; \
done

$CAT <<EOF

Checking PF…
EOF

# pfctl
if [[ `$SUDO $PFCTL -s info | $HEAD -1 | $TAIL -1` =~ "Status: Enabled" ]]; then
    echo "[✅] PF is enabled and running"
else
    $CAT <<EOF
[❌] PF isn't enabled! Troubleshooting:

sudo pfctl -si
less /var/log/pf.log
sudo /opt/local/bin/gpg --homedir /var/root/.gnupg --list-keys | grep -A2 -B1 -i dshield.org
sudo pfctl -Fall && sudo pfctl -ef /etc/pf.conf
EOF
fi

# hphosts
$CAT <<EOF

Checking hphosts files…
EOF

HPHOSTS_FILES=( \
	/etc/hosts-hphosts \
	/usr/local/etc/hosts.zip \
	/usr/local/etc/hphosts-partial.asp \
	/usr/local/etc/whitelist.txt \
	/usr/local/etc/blacklist.txt \
)

for FNAME in "${HPHOSTS_FILES[@]}" \
	; do \
	fname_exists; \
done

$CAT <<EOF

Checking /etc/hosts-hphosts creation…
EOF

# pfctl
if [ -f /etc/hosts-hphosts ]; then
    echo "[✅] /etc/hosts-hphosts exists"
else
    $CAT <<EOF
[❌] /etc/hosts-hphosts doesn't exist! Troubleshooting:

sudo /opt/local/bin/gpg --homedir /var/root/.gnupg --list-keys | grep -A2 -B1 -i hpHosts
sudo launchctl unload -w /Library/LaunchDaemons/net.hphosts.hosts.plist
sudo launchctl load -w /Library/LaunchDaemons/net.hphosts.hosts.plist
EOF
fi

# Proxy PAC and proxy chain
$CAT <<EOF

Checking proxy PAC and proxy chain files…
EOF

PROXY_FILES=( \
	$PROXY_PAC_DIRECTORY/proxy.pac.orig \
	$PROXY_PAC_DIRECTORY/proxy.pac \
	/usr/local/bin/easylist_pac.py \
	/usr/local/bin/adblock2privoxy \
        /usr/local/etc/proxy.pac \
	/usr/local/etc/adblock2privoxy/nginx.conf \
        /usr/local/etc/adblock2privoxy/css/default.html \
        /usr/local/etc/adblock2privoxy/privoxy/ab2p.action \
        /usr/local/etc/adblock2privoxy/privoxy/ab2p.filter \
        /usr/local/etc/adblock2privoxy/privoxy/ab2p.system.action \
        /usr/local/etc/adblock2privoxy/privoxy/ab2p.system.filter \
        /opt/local/etc/squid/squid.conf \
        /opt/local/var/squid/logs/cache.log \
        /opt/local/etc/privoxy/config \
        /opt/local/var/log/privoxy/logfile \
)

for FNAME in "${PROXY_FILES[@]}" \
	; do \
	fname_exists; \
done

$CAT <<EOF

Checking proxy status…
EOF

# squid
if [[ `$SUDO $LSOF -i ':3128' | $TAIL -1` && `$PS -ef | $GREP "/opt/local/sbin/squid -s" | $EGREP -v '(grep|daemondo)' | $WC -l` -eq 1 ]]; then
    echo "[✅] Squid is running properly"
else
    $CAT <<EOF
[❌] Squid isn't running properly! Troubleshooting:

sudo squid -k check
sudo less /opt/local/var/squid/logs/cache.log
sudo port unload squid4
sudo killall '(squid-1)'
sudo killall 'squid'
sleep 5
sudo port load squid4
EOF
fi

# privoxy
if [[ `$SUDO $LSOF -i ':8118' | $TAIL -1` ]]; then
    echo "[✅] Privoxy is running properly"
else
    $CAT <<EOF
[❌] Privoxy isn't running properly! Troubleshooting:

sudo less /opt/local/var/log/privoxy/logfile
sudo port unload privoxy
sudo port load privoxy
EOF
fi

# Privoxy configuration http://p.p/ via proxy server
if ! [[ `( http_proxy=http://${PROXY_SERVER}:3128; $CURL -s --head http://p.p/ | $HEAD -n 1 | $GREP "HTTP/1.\d [23]\d\d" )` ]]; then
    echo "[✅] Privoxy config http://p.p/ via http://${PROXY_SERVER}:3128 is running properly"
else
    $CAT <<'EOF'
[❌] Privoxy config http://p.p/ via http://${PROXY_SERVER}:3128 isn't running properly! Troubleshooting:

sudo less /opt/local/var/log/privoxy/logfile
sudo port unload privoxy
sudo port load privoxy
EOF
fi

# nginx
if [[ `$SUDO $LSOF -i ':8119' | $TAIL -1` ]]; then
    echo "[✅] nginx is running properly"
else
    $CAT <<'EOF'
[❌] nginx isn't running properly! Troubleshooting:

sudo ps -f `cat /opt/local/var/run/nginx/nginx-adblock2privoxy.pid`
sudo launchctl unload -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist
sudo launchctl load -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist
EOF
fi

# proxy.pac on proxy server
if ! [[ `$CURL -s --head http://${PROXY_PAC_SERVER}/proxy.pac | $HEAD -n 1 | $GREP "HTTP/1.\d [23]\d\d"`  ]]; then
    echo "[✅] Web server for http://${PROXY_PAC_SERVER}/proxy.pac is running properly"
else
    $CAT <<EOF
[❌] Web server for http://${PROXY_PAC_SERVER}/proxy.pac isn't running properly! Troubleshooting:

sudo apachectl start
EOF
fi

# blackhole on proxy server
if ! [[ `$CURL -s --head http://${PROXY_SERVER}:8119/ | $HEAD -n 1 | $GREP "HTTP/1.[01] [23]\d\d"` ]]; then
    echo "[✅] Blackhole server for http://${PROXY_SERVER}:8119/ is running properly"
else
    $CAT <<EOF
[❌] Blackhole server for http://${PROXY_SERVER}:8119/ isn't running properly! Troubleshooting:

sudo ps -f \`cat /opt/local/var/run/nginx/nginx-adblock2privoxy.pid\`
sudo launchctl unload -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist
sudo launchctl load -w /Library/LaunchDaemons/com.github.essandess.adblock2privoxy.nginx.plist
EOF
fi
