#!/usr/bin/perl -w

# This is a Cisco NetFlow datagram collector

# Netflow protocol reference:
# http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_0/nfc_ug/nfcform.htm

use strict;
use warnings;
use IO qw(Socket);
use Socket;
use Carp;
use POSIX qw(strftime);
use Getopt::Long;

############################################################################

sub timestamp()
{
	return strftime "%Y-%m-%dT%H:%M:%S", localtime;
}

sub fuptime($)
{
	my $t = shift;
	my $r = "";
	my $tmp;
	
	# Milliseconds
	$tmp = $t % 1000;
	$r = sprintf ".%03u%s", $tmp, $r;

	# Seconds
	$t = int($t / 1000);
	$tmp = $t % 60;
	$r = "${tmp}s${r}";

	# Minutes
	$t = int($t / 60);
	$tmp = $t % 60;
	$r = "${tmp}m${r}" if $tmp;

	# Hours
	$t = int($t / 60);
	$tmp = $t % 24;
	$r = "${tmp}h${r}" if $tmp;

	# Days
	$t = int($t / 24);
	$tmp = $t % 7;
	$r = "${tmp}d${r}" if $tmp;

	# Weeks
	$t = int($t / 7);
	$tmp = $t % 52;
	$r = "${tmp}w${r}" if $tmp;

	# Years
	$t = int($t / 52);
	$r = "${tmp}y${r}" if $tmp;

	return $r;
}

sub do_listen($)
{
	my $port = shift
		or confess "No UDP port specified";
        my $socket = IO::Socket::INET->new (Proto=>'udp', LocalPort=>$port)
		or croak "Couldn't open UDP socket: $!";

	return $socket;
}

sub process_nf_v1($$)
{
	my $sender = shift;
	my $pkt = shift;
	my %header;
	my %flow;
	
	%header = qw();

	($header{ver}, $header{flows}, $header{uptime}, $header{secs}, 
	 $header{nsecs}) = unpack("nnNNNNCC", $pkt);

	if (length($pkt) < (16 + (48 * $header{flows}))) {
		printf STDERR timestamp()." Short Netflow v.1 packet: %d < %d\n",
		    length($pkt), 16 + (48 * $header{flows});
		return;
	}

	printf timestamp() . " HEADER v.%u (%u flow%s)\n", $header{ver},
	    $header{flows}, $header{flows} == 1 ? "" : "s";

	for(my $i = 0; $i < $header{flows}; $i++) {
		my $off = 16 + (48 * $i);
		my $ptr = substr($pkt, $off, 52);

		%flow = qw();

		(my $src1, my $src2, my $src3, my $src4,
		 my $dst1, my $dst2, my $dst3, my $dst4, 
		 my $nxt1, my $nxt2, my $nxt3, my $nxt4, 
		 $flow{in_ndx}, $flow{out_ndx}, $flow{pkts}, $flow{bytes}, 
		 $flow{start}, $flow{finish}, $flow{src_port}, $flow{dst_port}, 
		 my $pad1, $flow{protocol}, $flow{tos}, $flow{tcp_flags}) =
		    unpack("CCCCCCCCCCCCnnNNNNnnnCCC", $ptr);

		$flow{src} = sprintf "%u.%u.%u.%u", $src1, $src2, $src3, $src4;
		$flow{dst} = sprintf "%u.%u.%u.%u", $dst1, $dst2, $dst3, $dst4;
		$flow{nxt} = sprintf "%u.%u.%u.%u", $nxt1, $nxt2, $nxt3, $nxt4;

		printf timestamp() . " " .
		    "from %s started %s finish %s proto %u %s:%u > %s:%u %u " . 
		    "packets %u octets\n",
		    inet_ntoa($sender),
		    fuptime($flow{start}), fuptime($flow{finish}), 
		    $flow{protocol}, 
		    $flow{src}, $flow{src_port}, $flow{dst}, $flow{dst_port}, 
		    $flow{pkts}, $flow{bytes};
	}
}

############################################################################

# Commandline options
my $debug = 0;
my $port;
#		Long option		Short option
GetOptions(	'debug+' => \$debug,	'd+' => \$debug,
		'port=i' => \$port,	'p=i' => \$port);

# Unbuffer output
$| = 1;

die "You must specify a port (collector.pl -p XXX).\n" unless $port;

# Main loop - receive and process a packet
for (;;) {
	my $socket;
	my $from;
	my $payload;
	my $ver;
	my $failcount = 0;
	my $netflow;
	my $junk;
	my $sender;

	# Open the listening port if we haven't already
	$socket = do_listen($port) unless defined $socket;

	# Fetch a packet
	$from = $socket->recv($payload, 8192, 0);
	
	($junk, $sender) = unpack_sockaddr_in($from);

	# Reopen listening socket on error
	if (!defined $from) {
		$socket->close;
		undef $socket;

		$failcount++;
		die "Couldn't recv: $!\n" if ($failcount > 5);
		next; # Socket will be reopened at start of loop
	}
	
	if (length($payload) < 16) {
		printf STDERR timestamp()." Short packet recevied: %d < 16\n",
		    length($payload);
		next;
	}

	# The version is always the first 16 bits of the packet
	($ver) = unpack("n", $payload);

	if	($ver == 1)	{ process_nf_v1($sender, $payload); }
	else {
		printf STDERR timestamp()." Unsupported netflow version %d\n",
		    $ver;
		next;
	}
	
	undef $payload;
	next;	
}

exit 0;
