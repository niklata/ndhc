# Copyright (c) 2007-2008 Roy Marples <roy@marples.name>
# All rights reserved. Released under the 2-clause BSD license.

ndhc_depend()
{
	program start /sbin/ndhc
	after interface
	provide dhcp
}

_config_vars="$_config_vars dhcp ndhc"

ndhc_start()
{
	local args= opt= opts= pidfile="/var/run/ndhc-${IFACE}.pid"
	local sendhost=true
	local leasefile="/var/state/${IFACE}.lease"

	eval args=\$ndhc_${IFVAR}

	# Get our options
	eval opts=\$dhcp_${IFVAR}
	[ -z "${opts}" ] && opts=${dhcp}

	# # Map some generic options to ndhc
	# for opt in ${opts}; do
	# 	case "${opt}" in
	# 		nodns) args="${args} --env PEER_DNS=no";;
	# 		nontp) args="${args} --env PEER_NTP=no";;
	# 		nogateway) args="${args} --env PEER_ROUTERS=no";;
	# 		nosendhost) sendhost=false;
	# 	esac
	# done

	# [ "${metric:-0}" != "0" ] && args="${args} --env IF_METRIC=${metric}"

	ebegin "Running ndhc"

	case " ${args} " in
		*" --quit "*|*" -q "*) x="/sbin/ndhc";;
		*) x="start-stop-daemon --start --exec /sbin/ndhc \
			--pidfile ${pidfile} --";;
	esac

	case " ${args} " in
		*" --hostname="*|*" -h "*|*" -H "*);;
		*)
			if ${sendhost}; then
				local hname="$(hostname)"
				if [ "${hname}" != "(none)" ] && [ "${hname}" != "localhost" ]; then
					args="${args} --hostname='${hname}'"
				fi
			fi
			;;
	esac

	# delay until carrier is up
	ip link set "${IFACE}" up
	ip link show "${IFACE}" | grep NO-CARRIER >/dev/null 2>&1
	while [ "$?" != "1" ]; do
	    sleep 1
	    ip link show "${IFACE}" | grep NO-CARRIER >/dev/null 2>&1
	done

	eval "${x}" "${args}" -r `cat /etc/firewall/tmp/OLDEXTIP` \
		-n -i "${IFACE}" -u "ndhc" -C "/var/lib/ndhc" \
		-p "${pidfile}" -l "${leasefile}" >/dev/null
	eend $? || return 1

	_show_address
	return 0
}

ndhc_stop()
{
	local pidfile="/var/lib/ndhc/var/run/ndhc-${IFACE}.pid" opts=
	[ ! -f "${pidfile}" ] && return 0

	# Get our options
	eval opts=\$dhcp_${IFVAR}
	[ -z "${opts}" ] && opts=${dhcp}

	ebegin "Stopping ndhc on ${IFACE}"
	case " ${opts} " in
		*" release "*)
			start-stop-daemon --stop --quiet --oknodo --signal USR2 \
				--exec /sbin/ndhc --pidfile "${pidfile}"
			;;
	esac

	start-stop-daemon --stop --exec /sbin/ndhc --pidfile "${pidfile}"
	eend $?
}
