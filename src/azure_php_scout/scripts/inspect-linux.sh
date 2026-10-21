#!/bin/sh
# Fixed, bounded PHP inventory. No installations, config changes, or PHP code.
# The Azure agent executes this with elevated privileges and records its own logs.
LC_ALL=C
export LC_ALL
budget=0
limited=no
binary_count=0
package_count=0
binary_errors=0
probe_uid=$(id -u nobody 2>/dev/null)
probe_gid=$(id -g nobody 2>/dev/null)
encode() { printf '%s' "$1" | base64 | tr -d '\r\n'; }
emit() {
    line=$1
    if [ $((budget + ${#line} + 1)) -le 3200 ]; then
        printf '%s\n' "$line"
        budget=$((budget + ${#line} + 1))
    else
        limited=yes
    fi
}
printf 'SCOUT_GUEST_BEGIN_V1\nOS|Linux\n'
if ! command -v base64 >/dev/null 2>&1; then
    printf 'ERROR|base64 is unavailable\nSCOUT_GUEST_END_V1\n'
    exit 1
fi
# Prefer web SAPIs before CLI. Only explicit installation roots are inspected.
for binary in /usr/sbin/php-fpm* /usr/bin/php-cgi* /usr/bin/php /usr/bin/php[0-9]* \
    /usr/local/bin/php /usr/local/sbin/php-fpm /opt/remi/php*/root/usr/bin/php \
    /opt/plesk/php/*/bin/php /usr/local/php*/bin/php; do
    [ -f "$binary" ] && [ -x "$binary" ] || continue
    printf '%s\n' "${binary##*/}" | awk '$0 ~ /^(php|php-fpm|php-cgi)([0-9.]+)?$/ {found=1} END {exit !found}' || continue
    if [ "$binary_count" -ge 8 ]; then limited=yes; break; fi
    binary_count=$((binary_count + 1))
    # Never execute an installed binary as root. Drop UID/GID/supplementary groups
    # and forbid privilege gains; -n skips php.ini and timeout bounds the probe.
    if command -v timeout >/dev/null 2>&1 && command -v setpriv >/dev/null 2>&1 \
        && [ -n "$probe_uid" ] && [ "$probe_uid" -gt 0 ] \
        && [ -n "$probe_gid" ] && [ "$probe_gid" -gt 0 ]; then
        version=$(setpriv --reuid="$probe_uid" --regid="$probe_gid" --clear-groups --no-new-privs \
            timeout 3 "$binary" -n -v 2>/dev/null | awk 'NR==1 && $1=="PHP" {print $2; exit}')
        case "$version" in
            [0-9]*.[0-9]*.[0-9]*)
                if [ ${#binary} -le 160 ] && [ ${#version} -le 64 ]; then
                    emit "RUNTIME|$version|$(encode "$binary")|binary"
                else limited=yes; fi ;;
            *) binary_errors=$((binary_errors + 1)) ;;
        esac
    else
        binary_errors=$((binary_errors + 1))
    fi
done
package_tool=unavailable
if command -v dpkg-query >/dev/null 2>&1; then
    package_tool=dpkg
    packages=$(dpkg-query -W -f='${binary:Package}|${Version}|${db:Status-Status}\n' 'php*' 2>/dev/null |
        awk -F'|' '$1 ~ /^php[0-9.]*-(cli|fpm|cgi|common)(:[A-Za-z0-9_-]+)?$/ && $3=="installed" {print $1 "|" $2}' | head -n 17)
elif command -v rpm >/dev/null 2>&1; then
    package_tool=rpm
    packages=$(rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null |
        awk -F'|' '$1 ~ /^php([0-9.]+(-php)?)?(-(cli|fpm|cgi|common))?$/ {print}' | head -n 17)
fi
# Split only on newlines; package fields are base64 encoded before emission.
saved_ifs=$IFS
IFS='
'
for package in $packages; do
    if [ "$package_count" -ge 16 ]; then limited=yes; break; fi
    package_count=$((package_count + 1))
    name=${package%%|*}
    version=${package#*|}
    if [ ${#name} -le 64 ] && [ ${#version} -le 96 ]; then
        emit "PACKAGE|$(encode "$name")|$(encode "$version")"
    else limited=yes; fi
done
IFS=$saved_ifs
process=unknown
if command -v ps >/dev/null 2>&1; then
    names=$(ps -eo comm= 2>/dev/null)
    if [ -n "$names" ]; then
        process=no
        if printf '%s\n' "$names" | awk '$1 ~ /^(php|php-cgi|php-fpm)([0-9.]*)?$/ {found=1} END {exit !found}'; then process=yes; fi
    fi
fi
printf 'PROCESS|%s\nPACKAGES|%s\nBINARY_ERRORS|%s\nLIMIT|%s\nSCOUT_GUEST_END_V1\n' \
    "$process" "$package_tool" "$binary_errors" "$limited"
