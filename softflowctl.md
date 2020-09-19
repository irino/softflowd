* * *

SOFTFLOWCTL(8) BSD System Manager's Manual SOFTFLOWCTL(8)

**NAME**

**softflowctl** -- Remote control program for softflowd

**SYNOPSIS**

**softflowctl** [ **-h** ] [ **-c  ** _ctl_sock_ ] _command_

**DESCRIPTION**

**softflowctl** is a remote control program used to control a running
softflowd(8) daemon.

The command line options are as follows:

**-c** _ctlsock_

Specify an alternate location for the remote control socket. Default is
_/var/run/softflowd.ctl_

**-h**

Display command line usage information.

**COMMANDS** _  
shutdown_

Ask softflowd(8) to gracefully exit. This is equivalent to sending it a
SIGTERM or SIGINT.

_exit_

Ask softflowd(8) to immediately exit. No flow expiry processing or data export
is performed.

_expire-all_

Immediately expire all tracked flows.

_delete-all_

Immediately delete all tracked flows. No flow expiry processing or data export
is performed.

_statistics_

Return statistics collected by softflowd(8) on expired flows.

_debug+_

Increase the debugging level of softflowd(8)

_debug-_

Decrease the debugging level.

_stop-gather_

Stops network data collection by softflowd(8).

_start-gather_

Resumes network data collection.

_dump-flows_

Return information on all tracked flows.

_timeouts_

Print information on flow timeout parameters.

_send-template_

Resend a NetFlow v.9 template record before the next flow export. Has no
effect for other flow export versions.

**BUGS**

All times are unconditionally displayed in UTC, regardless of the system
timezone. Please report bugs in softflowctl to
https://github.com/irino/softflowd/issues

**AUTHORS**

Damien Miller <djm@mindrot.org>  
Hitoshi Irino (current maintainer) <irino@sfc.wide.ad.jp>

**SEE ALSO**

softflowd(8)

BSD October 18, 2002 BSD

* * *

