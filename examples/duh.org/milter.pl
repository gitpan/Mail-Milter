#!/usr/local/bin/perl -w -I../../lib
# $Id: milter.pl,v 1.23 2004/07/30 17:31:47 tvierling Exp $
#
# Copyright (c) 2002 Todd Vierling <tv@pobox.com> <tv@duh.org>.
# This file is hereby released to the public and is free for any use.
#
# This is the actual Mail::Milter instance running in production on the
# duh.org mail server as of the RCS datestamp above.  This may be useful
# to you as a template or suggestion for your own milter installation.
#

use strict;
use warnings;

use Carp qw{verbose};
use Mail::Milter::Chain;
use Mail::Milter::Module::ConnectASNBL;
use Mail::Milter::Module::ConnectDNSBL;
use Mail::Milter::Module::ConnectMatchesHostname;
use Mail::Milter::Module::ConnectRegex;
use Mail::Milter::Module::HeaderFromMissing;
use Mail::Milter::Module::HeaderRegex;
use Mail::Milter::Module::HeloRawLiteral;
use Mail::Milter::Module::HeloRegex;
use Mail::Milter::Module::HeloUnqualified;
use Mail::Milter::Module::MailDomainDNSBL;
use Mail::Milter::Module::VirusBounceSpew;
use Mail::Milter::Wrapper::DeferToRCPT;
use Mail::Milter::Wrapper::RejectMsgEditor;
use Sendmail::Milter 0.18;
use Socket;

#
# This file is arranged in top-down order.  Objects constructed
# closer to the top have deeper nesting into the milter tree,
# and will be reached last; conversely, objects at the bottom are
# reached first.
#

##### Bad headers
#
# It would be nice if we rejected before DATA, but alas, that's not
# always possible.  However, there are some distinct spamsigns
# present in mail headers.  YMMV.
#

my $bad_headers = &HeaderRegex(
	# these don't belong in transit
	'^X-UIDL: ',
);

my $spam_headers = &HeaderRegex(
	# known spamware
	'^X-(?:AD2000-Serial|Advertisement):',
	'^X-Mailer: (?:Mail Bomber|Accucast)',

	# older Pegasus does this, but *lots* of spamware does too
	'^Comments: Authenticated sender is',

	# the law says you must tag, and my sanity says I must block
	'^Subject: ADV ?:',
)->set_message(
	'NO UCE means NO SPAM (no kidding!)'
);

my $disallowed_encodings = '(?:'.join('|', qw{
	big5
	koi8-r
	windows-125.
}).')';

my $disallowed_encoding_headers = &HeaderRegex(
	'^Subject: =\?'.$disallowed_encodings.'\?',
	'^Content-Type:.*\scharset='.$disallowed_encodings,
)->set_message(
	'Your international character set is not understood here; re-send your message using standard ISO-8859 or UTF8 encoding'
);

my $cloaked_encoding_headers = &HeaderRegex(
	'^(?:Subject|From|To): =\?(?:US-ASCII|ISO-8859-1)\?'
)->set_message(
	'Encoded US-ASCII or ISO-8859-1 headers are not allowed due to severe abuse; re-send your message without the encoding'
);

##### Dynamic pool rDNS, with exceptions.
# 
# "Good" ISPs partition their dynamic pools into easy-to-identify
# subdomains.  But some don't, so here we go....
#

my $dynamic_rdns = new Mail::Milter::Chain(
	# Grrr.  I shouldn't have to do this.  GET REAL rDNS, PEOPLE!
	&ConnectRegex(
		'\.(?:biz\.rr\.com|ipxserver\.de|knology\.net|netrox\.net|dq1sn\.easystreet\.com|(?:scrm01|snfc21)\.pacbell\.net)$',
		'^wsip-[\d-]+\..*\.cox\.net$',
	)->accept_match(1),

	&ConnectRegex(
		'^cablelink[\d-]+\.intercable\.net$',
	)->set_message(
		'Dynamic pool:  Connecting hostname %H is a dynamic address.  If this mail has been rejected in error'
	),
	&ConnectMatchesHostname->set_message(
		'Dynamic pool:  Connecting hostname %H contains IP address %A.  If this mail has been rejected in error'
	),
)->accept_break(1);

##### Custom milter modules
#
# Don't ask and don't use.  These are duh.org site-specific, and are likely
# of zero usefulness to anyone else.
#

# (empty)

##### Per-country restrictions
#
# The following special hack has existed in the duh.org mail config in some
# form for a very long time.  It requires a proper /usr/share/misc/country
# file (originally from *BSD) to map the two-letter country codes back to
# their ISO numeric equivalents used in zz.countries.nerd.dk.
#

my @ccs = qw(AR BR CL CN CO JO KR MX MY NG PK SG TH TM TW);
my %ccs = map { $_ => 1 } @ccs;

my @zzccs;

open(CC, '</usr/share/misc/country') || die $!;
while (<CC>) {
	s/#.*$//;
	s/\s+$//; # also strips newlines

	my @entry = split(/\t/);
	next unless @entry;

	if ($ccs{$entry[1]}) {
		$entry[3] =~ s/^0+//;
		push(@zzccs, inet_ntoa(pack('N', 0x7f000000 + $entry[3])));
	}
}
close(CC);

##### DNSBL checks
#
# There's quite a few used here, not all of which are appropriate for all
# sites.  My site is somewhere between "lenient" and "strict", but YMMV.
# Use with caution.
#

# ordering rationale: in each set, zones queried in an earlier set are
# queried first in subsequent sets so as to reuse named-cached values

my $country_msg = 'Access denied to %A: Due to excessive spam, we do not normally accept mail from your country';
my @country_dnsbls = (
	&ConnectDNSBL('zz.countries.nerd.dk', @zzccs)->set_message($country_msg),
);

my $relay_msg = 'Access denied to %A: This address is vulnerable to open-relay/open-proxy attacks (listed in %L)';
my @relayinput_dnsbls = (
	&ConnectDNSBL('combined.njabl.org', '127.0.0.2', '127.0.0.9')->set_message($relay_msg),
	&ConnectDNSBL('dnsbl.sorbs.net', (map "127.0.0.$_", (2,3,4,5,9)))->set_message($relay_msg),
	&ConnectDNSBL('list.dsbl.org')->set_message($relay_msg),
	&ConnectDNSBL('relays.visi.com')->set_message($relay_msg),
);

my $dynamic_msg = 'Dynamic pool:  Connecting address %A is a dynamic address (listed in %L).  If this mail has been rejected in error';
my @dynamic_dnsbls = (
	&ConnectDNSBL('combined.njabl.org', '127.0.0.3')->set_message($dynamic_msg),
	&ConnectDNSBL('dnsbl.sorbs.net', '127.0.0.10')->set_message($dynamic_msg),
);

# ...and these use the default message.
my @generic_dnsbls = (
	&ConnectDNSBL('combined.njabl.org', '127.0.0.4'),
	&ConnectDNSBL('l1.spews.dnsbl.sorbs.net'),
#	&ConnectDNSBL('spews.blackholes.us'), # alternate for SPEWS
	&ConnectDNSBL('sbl-xbl.spamhaus.org'),
);

my @rhsbls = (
	&MailDomainDNSBL('nomail.rhsbl.sorbs.net'),
	&MailDomainDNSBL('rhsbl.ahbl.org'),
	&MailDomainDNSBL('bogusmx.rfc-ignorant.org'),
);

##### Inner chain: main collection of checks
#
# As well as the more complicated checks above, I've added some
# simpler ones directly in-line below.
#

my $inner_chain = new Mail::Milter::Chain(
	&ConnectASNBL('asn.routeviews.org',
		11969,	# Thought to be Dynamic Pipe
		14479,	# Webfinity (Dynamic Pipe)
		19961,	# Dynamic Pipe
	),
	$dynamic_rdns,
	@country_dnsbls,
	@relayinput_dnsbls,
	@dynamic_dnsbls,
	@generic_dnsbls,
	&HeloUnqualified,
	&HeloRawLiteral,
	&HeloRegex(
		'^humblenet\.com$',
	),
	@rhsbls,
	&HeaderFromMissing,
	$bad_headers,
	$spam_headers,
	$disallowed_encoding_headers,
	$cloaked_encoding_headers,
	&VirusBounceSpew,
#	{
#		connect => sub {
#			my $ctx = shift;
#			my $host = shift;
#			if ($host =~ /^\[/) {
#				$ctx->setreply(451, '4.7.0', "Host $host has no reverse DNS -- Please email postmaster\@duh.org for assistance.");
#				return SMFIS_TEMPFAIL;
#			}
#			SMFIS_CONTINUE;
#		},
#	},
	{
		envfrom => sub {
			my $ctx = shift;
			if (shift ne '<>') {
				$ctx->setpriv(undef);
				return SMFIS_ACCEPT;
			}
			$ctx->setpriv(0);
			SMFIS_CONTINUE;
		},
		envrcpt => sub {
			my $ctx = shift;
			my $nullcount = $ctx->getpriv;
			$ctx->setpriv(++$nullcount);

			if ($nullcount > 1) {
				$ctx->setreply(554, '5.7.0', 'Null sender <> mail should have only one recipient');
				return SMFIS_REJECT;
			}
			SMFIS_CONTINUE;
		},
		eoh => sub {
			my $ctx = shift;
			my $nullcount = $ctx->getpriv;
			if ($nullcount > 1) {
				$ctx->setreply(554, '5.7.0', 'Null sender <> mail should have only one recipient');
				return SMFIS_REJECT;
			}
			SMFIS_ACCEPT;
		},
	},
);

##### Error message rewriter: point user to postmaster@duh.org
#
# Since postmaster@duh.org is exempted below, prompting the user
# to send mail there is an in-band way to receive messages about
# blocking errors from legit users.  This is much more desirable
# then redirecting to a URL.
#

my $rewritten_chain = &RejectMsgEditor($inner_chain, sub {
	s,$, -- Please e-mail postmaster\@duh.org for assistance.,;
});

##### Outer chain: "postmaster" recipients get everything; exempt hosts.
#
# This is accomplished by using a chain in "accept_break" mode,
# where connect from particular hosts (like localhost) and envrcpt
# on "postmaster@" returns SMFIS_ACCEPT and thus skips any other
# return value pending.
#
# For the postmaster@ check to work, this requires funneling errors
# through "DeferToRCPT" in order to ensure that the RCPT TO: phase
# is reached.
#

# First fetch the /etc/mail/relay-domains list.
# Note that I already put "localhost" in that file, so it's not
# specified again in the call to ConnectRegex below.

my @relay_domain_regexes;
open(I, '</etc/mail/relay-domains');
while (<I>) {
	chomp;
	s/#.*$//;
	s/^\s+//;
	s/\s+$//;
	next if /^$/;

	# Dots are escaped to make them valid in REs.
	s/\./\\\./g;
	if (/^[0-9\\\.]+$/) {
		# IP address; match a literal.

		s/$/\]/ unless /\\\.$/; # if not ending in a dot, match exactly
		push(@relay_domain_regexes, qr/^\[$_/i);
	} else {
		# Domain/host name; match string as-is.

		s/^/\^/ unless /^\\\./; # if not starting with a dot, match exactly
		push(@relay_domain_regexes, qr/$_$/i);
	}
}
close(I);

my $outer_chain = new Mail::Milter::Chain(
	&ConnectRegex(
		@relay_domain_regexes,
	)->accept_match(1),
	{
		# add delays to certain parts of transactions to trip ratware
		# (this requires setting T=R:4m or so in sendmail.mc)
		connect => sub {
			my $ctx = shift;
			my $host = shift;
			$ctx->setpriv(1) if ($host =~ /^\[/); # flag no rDNS
			SMFIS_CONTINUE;
		},
		envfrom => sub {
			my $ctx = shift;
			sleep 120 if $ctx->getpriv(); # no rDNS
			SMFIS_CONTINUE;
		},
		envrcpt => sub {
			my $ctx = shift;
			sleep 30 if $ctx->getpriv(); # no rDNS
			SMFIS_CONTINUE;
		},
	},
	{
		envrcpt => sub {
			shift; # $ctx
			(shift =~ /^<?postmaster\@/i) ?
				SMFIS_ACCEPT : SMFIS_CONTINUE;
		},
	},
	&DeferToRCPT($rewritten_chain),
	require('greylist.pl'),
)->accept_break(1);

##### The milter itself.
#
# I personally use Sendmail::PMilter under the covers, but I'm
# deliberately using the Sendmail::Milter API below to make this
# example work outside my installation.
#

Sendmail::Milter::auto_setconn('pmilter');
Sendmail::Milter::register('pmilter', $outer_chain, SMFI_CURR_ACTS);
Sendmail::Milter::main(25, 50);
