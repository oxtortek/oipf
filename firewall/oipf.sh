#!/bin/bash

echo
echo "OIPF version #VERSION#"
echo

# Limits the amount of packages logged to syslog.
# Set it to 0 for debugging purposes. Default is 1.
#
#LIMITED_LOGGING=0
LIMITED_LOGGING=1

# Logging system: ULOG and NFLOG with ulogd are supported.
# Since ulogd 2.0 (the version bundled with Ubuntu Trusty), NFLOG is prefered
# over ULOG and ULOG must be seperatly enabled in /etc/ulogd.conf
LOGGING_SYSTEM=NFLOG

# Inserts directly after ruleset flushing two rules allowing
# incomming ssh traffic from everywhere on port 22.
#
# +++ Use with care and disable in production environment! +++
#
INITIAL_SSH=0

# Hostname definitions. This should with the output from `hostname -s`
HOSTNAME_MASTER="fw-master"
HOSTNAME_SLAVE="fw-slave"

# Slave node ip address for sync-connections
SLAVEIP="0.0.0.0"

# basic configuration dir in /etc
ETCDIR="/etc/oipf"

# Where to search for rule-specific config files (*.fwr)
CONFDIR="${ETCDIR}/conf.d"

# Where to search for rule files (*.fwr)
RULEDIR="${ETCDIR}/rules.d"

# Where to search for library files (*.fwl)
LIBDIR="/usr/share/oipf/libs.d"

# Where to place temporary files in?
TMPDIR="/var/lib/oipf/tmp"

# Path to 'iptables-save' dumpfile
IPTDUMPS="/var/lib/oipf/iptdumps"
IPTDUMP_MASTER="${IPTDUMPS}/master"
IPTDUMP_SLAVE="${IPTDUMPS}/slave"

# Alternative name for .git folder
GITDIR="/var/lib/oipf/.oipf-git"

# Parts that should be synced with slave node
SYNCPARTS="${ETCDIR}"
SYNCPARTS="${SYNCPARTS} /etc/apt"
SYNCPARTS="${SYNCPARTS} /etc/default/isc-dhcp-server"
SYNCPARTS="${SYNCPARTS} /etc/default/setkey"
SYNCPARTS="${SYNCPARTS} /etc/dhcp/dhcpd.conf"
SYNCPARTS="${SYNCPARTS} /etc/hosts"
SYNCPARTS="${SYNCPARTS} /etc/init.d/ip-xfrm"
SYNCPARTS="${SYNCPARTS} /etc/init.d/racoon.pacemaker"
SYNCPARTS="${SYNCPARTS} /etc/init.d/snmpd.pacemaker"
SYNCPARTS="${SYNCPARTS} /etc/ipsec-tools.conf"
SYNCPARTS="${SYNCPARTS} /etc/racoon"
SYNCPARTS="${SYNCPARTS} /etc/resolv.conf"
SYNCPARTS="${SYNCPARTS} /etc/snmp/snmpd.conf"
SYNCPARTS="${SYNCPARTS} /etc/sysctl.d/xfrm4_gc_thresh.conf"
SYNCPARTS="${SYNCPARTS} /usr/lib/ocf/resource.d/triplesense"
SYNCPARTS="${SYNCPARTS} /var/cache/apt/archives"
SYNCPARTS="${SYNCPARTS} /var/lib/dhcp"
SYNCPARTS="${SYNCPARTS} ${IPTDUMP_MASTER}"

# Where to place the oipf.lock file?
LOCKFILE="/var/run/oipf.lock"

# Time to wait for a lock
LOCKTIMEOUT=120

# load config if present
test -f /etc/oipf/oipf.conf && . /etc/oipf/oipf.conf


##############################################################################
# MAIN

# check /var/lib/iptables
test -d $IPTDUMPS || mkdir -p $IPTDUMPS

# check $TMPDIR
test -d $TMPDIR || mkdir -p $TMPDIR

. /usr/share/oipf/base-functions.fwl
detect_hostrole
detect_hostrole_override $@

echo "Detected role: $hostrole"
if [ "$hostrole_override" != "undefined" ] && [ "$hostrole_override" != "$hostrole" ]; then
  echo "*** Overriding hostrole detection with \"--force-role $hostrole_override\""
  echo "*** Setting role to: $hostrole_override"
  hostrole=$hostrole_override
fi
if [ $hostrole == 'undefined' ]; then
  echo "*** Hostrole is undefined! Exiting now...  ***"
  echo "Please check the HOSTNAME_MASTER and HOSTNAME_SLAVE vars in /etc/oipf/oipf.conf"
  exit 1
fi

if [ $# = 1 ] && [ "$1" = '--clean-lock' ]; then
  test -f ${LOCKFILE} && rm -f ${LOCKFILE}
  exit 0
fi

echo
test -d $TMPDIR && find $TMPDIR -type f ! -name '*.status' -exec rm {} \;
case "$1" in
  load|start)
    # try to get an exclusive lock
    echo -n "Waiting to get an exclusive lock on ${LOCKFILE} ... "
    get_exclusive_lock && (echo 'ok.') || (echo "failed, timeout of ${LOCKTIMEOUT} seconds reached!"; exit 1)
    echo
    initial_kernel_config
    if [ -f "$IPTDUMPS/$hostrole" ]; then
      echo -n "Loading rules and counters from $IPTDUMPS/$hostrole ..."
      /sbin/iptables-restore --counters < $IPTDUMPS/$hostrole
      retval=$?
      initial_kernel_config
      if [ $retval -eq 0 ]; then
        set_status ok
        echo " done"
      else
        set_status error
        echo " failed"
      fi
      echo
      exit $retval
    else
      echo "$IPTDUMPS/$hostrole not found."
      echo "Could not load data from file. Exiting."
      echo
      set_status error undefined
      exit 1
    fi
    ;;
  save)
    # try to get an exclusive lock
    echo -n "Waiting to get an exclusive lock on ${LOCKFILE} ... "
    get_exclusive_lock && (echo 'ok.') || (echo "failed, timeout of ${LOCKTIMEOUT} seconds reached!"; exit 1)
    echo
    echo -n "Saving rules and counters to $IPTDUMPS/$hostrole ..."
    /sbin/iptables-save --counters > $IPTDUMPS/$hostrole
    retval=$?
    if [ $retval -eq 0 ]; then echo " done"
    else echo " failed"; fi
    git_commit_msg="Cmd 'oipf save' called by $SUDO_USER at $(date '+%Y-%M-%d %H:%m:%S')."
    echo "Comitting rules and configs to GIT ..."
    git --git-dir=$GITDIR --work-tree=$ETCDIR add -v .
    git --git-dir=$GITDIR --work-tree=$ETCDIR commit -a -m "$git_commit_msg"
    echo
    exit $retval
    ;;
  stop)
    exit 0
    ;;
  reload)
    # try to get an exclusive lock
    echo -n "Waiting to get an exclusive lock on ${LOCKFILE} ... "
    get_exclusive_lock && (echo 'ok.') || (echo "failed, timeout of ${LOCKTIMEOUT} seconds reached!"; exit 1)
    echo
    IPTABLES='/sbin/iptables'
    #IPSET='/usr/sbin/ipset'
    IPSET='/bin/true'
    ;;
  sync)
    # try to get an exclusive lock
    echo -n "Waiting to get an exclusive lock on ${LOCKFILE} ... "
    get_exclusive_lock && (echo 'ok.') || (echo "failed, timeout of ${LOCKTIMEOUT} seconds reached!"; exit 1)
    echo
    if [ "`hostname -s`" == "$HOSTNAME_SLAVE" ]; then
      echo "Only $HOSTNAME_MASTER is able to sync configs with $HOSTNAME_SLAVE."
      echo
      exit 1
    fi
    for part in ${SYNCPARTS}; do
      echo -n "Syncing $part via rsync with ${SLAVEIP} ..."
      rsync --archive --delete --exclude="ruleset-*.status" $part $SLAVEIP:`dirname $part`
      if [ $? -ne 0 ]; then break; fi
      echo " done"
    done
    echo -n "Syncing $IPTDUMP_SLAVE via rsync back from ${SLAVEIP} ..."
    rsync --archive --delete $SLAVEIP:$IPTDUMP_SLAVE `dirname $IPTDUMP_SLAVE`
    echo " done"
    echo
    exit 0
    ;;
  status)
    status=`get_status`
    if [ $? -eq 0 ]; then
      echo $status
      exit 0
    fi
    echo "undefined"
    exit 1
    ;;
  syntax)
    IPTABLES='/bin/true'
    IPSET='/bin/true'
    #IPSET='/usr/sbin/ipset'
    ;;
  git)
    shift 1
    git --git-dir=$GITDIR --work-tree=$ETCDIR $@
    exit $?
    ;;
  log)
    shift 1
    if [ -z "$@" ]; then
      tailcmd="tail -f /var/log/ulog/syslogemu.log"
    else
      tailcmd="tail -f /var/log/ulog/syslogemu.log | egrep --line-buffered --color '$@'"
    fi
    echo "Running command: ${tailcmd}"
    sh -c "$tailcmd"
    exit $?
    ;;
  glog)
    shift 1
    if [ -z "$@" ]; then
      echo "Search expression for egrep needed." >&2
      exit 1
    fi
    tailcmd="egrep '$@' /var/log/ulog/syslogemu.log | grep --line-buffered --color '$@'"
    echo "Running command: ${tailcmd}"
    sh -c "$tailcmd"
    exit $?
    ;;
  show)
    IPTABLES=/bin/true
    IPSET=/bin/true
    ;;
  help)
    man 8 oipf
    exit 0
    ;;
  *)
    cat <<EndOfMessage

Usage: $0 <help|load|save|reload|sync|syntax|show-vars|git|log> [git subcommand: log|diff|status]
       [--force-role <master|slave>]

help:   Displays the OIPF man page.
reload: Loads all libraries, config and rule files,
        builds netfilter rules and activates them
        in the kernel.
save:   Dumps all active rules to $IPTDUMPS/\$hostrole and
        commits all changes in $ETCDIR to GIT.
load:   Loads all rules from $IPTDUMPS/\$hostrole.
sync:   Synchronises firewall slave with firewall master.
syntax: This is a syntax check which loads /bin/true in
        place of /sbin/iptables. So you can detect all syntax
        errors in bash, before you load the ruleset and maybe
        lock yourself out.
show:   Usage: oipf show <subcommand>
        Subcommands:
        - vars:  Lists all defined objects from conf.d/*.fwc files.
        - rules: Lists active ruleset from kernelspace.
status: Outputs loaded ruleset master|slave or none, if no rules
        after system reboot are loaded for example.
        The status is saved in a file. If absent, status is undefined.
git:    GIT wrapper - sets the following parameters and calls GIT:
          --git-dir=$GITDIR
          --work-tree=$ETCDIR
log:    Calls tail -f /var/log/ulog/syslogemo.log optionally followed by egrep.
        To filter the output, you can specify a regular expression for egrep.
glog:   Calls egrep on the log file /var/log/ulog/syslogemo.log.
        To filter the output, you can specify a regular expression for egrep.

Additional information may be found in the manpage oipf(8).

EndOfMessage
    exit 1
    ;;
esac

sleep 1
# Flush all previously loaded ipsets
#$IPSET -F
#$IPSET -X

# Load libraries.
echo "Processing libraries in ${LIBDIR}"
for file in `ls ${LIBDIR}/*.fwl 2>/dev/null`; do . ${file}; done

# Load config files.
echo "Processing config files in ${CONFDIR}"
for file in `ls ${CONFDIR}/*.fwc 2>/dev/null`; do . ${file}; done

# Show variables, rules, etc if requested and exit gracefully
if [ "x$1" = 'xshow' ]; then
  case $2 in
    vars)
      echo
      echo 'Listing of all defined port variables:'
      set | grep '^p_' | sort | sed -r 's/^/  /'
      echo
      echo 'Listing of all defined interface variables:'
      set | grep '^IF_' | sort | sed -r 's/^/  /'
      echo
      echo 'Listing of all defined host and net variables:'
      set | grep -E '^(BCAST|IP|NET|IPLIST|NETLIST)_' | sort | sed -r 's/^/  /'
      ;;
    rules)
      echo
      echo 'Listing of active ruleset from kernelspace:'
      shift 2
      iptables -nvL $@
      ;;
    esac
  exit 0
fi

# Load appropriate modules.
# These lines are here in case rules are already in place and the script is ever rerun on the fly.
# We want to remove all rules and pre-exisiting user defined chains and zero the counters
# before we implement new rules.
$IPTABLES -t mangle -F
$IPTABLES -t mangle -X
$IPTABLES -t filter -F
$IPTABLES -t filter -X
$IPTABLES -t nat -F
$IPTABLES -t nat -X
# do not zeroing - this will confuse the dumpscripts...
#iptables -t filter -Z
#iptables -t nat -Z

# Initial SSH connection - be carefull!
# If you don't see a nice box, you should use a utf-8 charset!
if [ "x$INITIAL_SSH" == "x1" ]; then
  cols="\033[41m\033[1;37m"
  cole="\033[0m\033[0m"
  echo
  echo -e " $cols ╔══════════════════════════════════════════════════════════════════════════════════════╗ $cole"
  echo -e " $cols ║         +++ Warning: The following build-in ssh rules are still active! +++          ║ $cole"
  echo -e " $cols ║                  +++ Set INITIAL_SSH=0 after ssh rule setup! +++                     ║ $cole"
  echo -e " $cols ║ /sbin/iptables -I INPUT -p TCP --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT ║ $cole"
  echo -e " $cols ║ /sbin/iptables -I OUTPUT -p TCP --sport 22 -m state --state ESTABLISHED -j ACCEPT    ║ $cole"
  echo -e " $cols ╚══════════════════════════════════════════════════════════════════════════════════════╝ $cole"
  echo
  $IPTABLES -I INPUT -p TCP --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPTABLES -I OUTPUT -p TCP --sport 22 -m state --state ESTABLISHED -j ACCEPT
  # sleep 4
fi

# Set up a default DROP policy for the built-in chains.
# If we modify and re-run the script mid-session then (because we have a
# default DROP policy), what happens is that there is a small time period
# when packets are denied until the new rules are back in place. There
# is no period, however small, when packets we don't want are allowed.
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT DROP

## ============================================================
## Kernel flags
initial_kernel_config

## ============================================================
# RULES

echo -n "Loading buildin rules (pre) "

## LOOPBACK
# Allow unlimited traffic on the loopback interface.
$IPTABLES -A INPUT  -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

## SYN-FLOODING PROTECTION
# des geht so net... ich lass es mal stehen fuer Leute die nix zu tun
# haben..
# This rule maximises the rate of incoming connections. In order to do
# this we divert tcp packets with the SYN bit set off to a user-defined
# chain. Up to limit-burst connections can arrive in 1/limit seconds ...
# in this case 4 connections in one second. After this, one
# of the burst is regained every second and connections are allowed again.
# The default limit is 3/hour. The default limit burst is 5.
#
#$IPTABLES -N syn-flood
#$IPTABLES -A INPUT -i $IFACE -p tcp --syn -j syn-flood
#$IPTABLES -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
#$IPTABLES -A syn-flood -j DROP
## Make sure NEW tcp connections are SYN packets
#$IPTABLES -A INPUT -i $IFACE -p tcp ! --syn -m state --state NEW -j DROP

## FRAGMENTS
# I have to say that fragments scare me more than anything.
# Sending lots of non-first fragments was what allowed Jolt2 to
# effectively "drown" Firewall-1. Fragments can be overlapped, and the
# subsequent interpretation of such fragments is very OS-dependent
# (see this paper for details).
# I am not going to trust any fragments.
# Log fragments just to see if we get any, and deny them too.
ipt_chain_begin -r all -n FRAGMENTS
ipt_chain_end -r all -n FRAGMENTS
call_ipt -r all -A INPUT -i $IF_EXT -f -j FRAGMENTS

## SPOOFING
# Most of this anti-spoofing stuff is theoretically not really necessary
# with the flags we have set in the kernel above ... but you never know
# there isn't a bug somewhere in your IP stack.
#
# Refuse spoofed packets pretending to be from your IP address.
#call_ipt --role master -A INPUT -i $IF_EXT -s $IP_EXT -j DROP
# Refuse packets claiming to be from a Class A private network.
#call_ipt --role master -A INPUT -i $IF_EXT -s $NET_CLASS_A -j DROP
# Refuse packets claiming to be from a Class B private network.
#call_ipt --role master -A INPUT -i $IF_EXT -s $NET_CLASS_B -j DROP
# Refuse packets claiming to be from a Class C private network.
#call_ipt --role master -A INPUT -i $IF_EXT -s $NET_CLASS_C -j DROP
# Refuse Class D multicast addresses. Multicast is illegal as a source address.
#call_ipt --role all -A INPUT -s $NET_CLASS_D_MULTICAST -j DROP
# Refuse Class E reserved IP addresses.
#call_ipt --role all -A INPUT -s $NET_CLASS_E_RESERVED_NET -j DROP
# Refuse packets claiming to be to the loopback interface.
# Refusing packets claiming to be to the loopback interface protects against
# source quench, whereby a machine can be told to slow itself down by an
# icmp source quench to the loopback.
#call_ipt --role all -A INPUT  -i $IF_EXT -d $NET_LOOPBACK -j DROP

# Refuse broadcast address packets.
for bcast in $BROADCASTADDRESSES; do
  call_ipt --role all -A INPUT -d $bcast -j DROP
done

echo " done"

# Loading userdefined rules.
echo "Processing rule files in ${RULEDIR}"
for file in `ls ${RULEDIR}/*.fwr 2>/dev/null`; do . ${file}; done


echo -n "Loading buildin rules (post) "
## LOGGING
# You don't have to split up your logging like I do below, but I prefer
# to do it this way because I can then grep for things in the logs more
# easily. One thing you probably want to do is rate-limit the logging.
# I didn't do that here because it is probably best not too when you
# first set things up ... you actually really want to see everything
# going to the logs to work out what isn't working and why. You can
# implement logging with "-m limit --limit 6/h --limit-burst 5" (or similar)
# before the -j LOG in each case.
#

# # Any udp not already allowed is logged and then dropped.
# $IPTABLES -A INPUT -p udp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'UDP-IN: '
# $IPTABLES -A INPUT -p udp -j DROP
# $IPTABLES -A OUTPUT -p udp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'UDP-OUT: '
# $IPTABLES -A OUTPUT -p udp -j DROP
# $IPTABLES -A FORWARD -p udp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'UDP-FWD: '
# $IPTABLES -A FORWARD -p udp -j DROP
# # Any icmp not already allowed is logged and then dropped.
# $IPTABLES -A INPUT -p icmp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'ICMP-IN: '
# $IPTABLES -A INPUT -p icmp -j DROP
# $IPTABLES -A OUTPUT -p icmp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'ICMP-OUT: '
# $IPTABLES -A OUTPUT -p icmp -j DROP
# $IPTABLES -A FORWARD -p icmp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'ICMP-FWD: '
# $IPTABLES -A FORWARD -p icmp -j DROP
# # Any tcp not already allowed is logged and then dropped.
# $IPTABLES -A INPUT -p tcp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'TCP-IN: '
# $IPTABLES -A INPUT -p tcp -j DROP
# $IPTABLES -A OUTPUT -p tcp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'TCP-OUT: '
# $IPTABLES -A OUTPUT -p tcp -j DROP
# $IPTABLES -A FORWARD -p tcp $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'TCP-FWD: '
# $IPTABLES -A FORWARD -p tcp -j DROP
# # Anything else not already allowed is logged and then dropped.
# # It will be dropped by the default policy anyway ........ but let's be paranoid.
# $IPTABLES -A INPUT $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'PROTOCOL-X-IN: '
# $IPTABLES -A INPUT -j DROP
# $IPTABLES -A OUTPUT $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'PROTOCOL-X-OUT: '
# $IPTABLES -A OUTPUT -j DROP
# $IPTABLES -A FORWARD $LOGLIMIT -j NFLOG $LOGLEVEL --nflog-prefix 'PROTOCOL-X-OUT: '
# $IPTABLES -A FORWARD -j DROP
ipt_chain_end -r all -n INPUT
ipt_chain_end -r all -n OUTPUT
ipt_chain_end -r all -n FORWARD
echo " done"

# THE END
# ==================================================================

echo
set_status ok
exit 0
