#!/usr/local/bin/perl -w -I../../lib
# $Id: milter.pl,v 1.7 2004/03/25 18:59:03 tvierling Exp $
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
use Mail::Milter::Module::ConnectMatchesHostname;
use Mail::Milter::Module::ConnectRegex;
use Mail::Milter::Module::HeaderFromMissing;
use Mail::Milter::Module::HeaderRegex;
use Mail::Milter::Module::HeloRawLiteral;
use Mail::Milter::Module::HeloUnqualified;
use Mail::Milter::Wrapper::DeferToRCPT;
use Mail::Milter::Wrapper::RejectMsgEditor;
use Sendmail::Milter 0.18;

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
	# foreign encoded from/to/cc does not belong in message/rfc822
	'^(?:From|To|Cc): =\?[^\@]*\?=$',

	# ISO-8859-1 rarely needs encoding
	'^Subject: =\?iso-8859-1\?',

	# Disallowed languages which I can't speak anyway
	'^(From|To|Cc|Subject): =\?(Big5|windows-1251)\?',

	# these don't belong in transit
	'^X-UIDL: ',
);

my $spam_headers = &HeaderRegex(
	# known spamware
	'^X-(AD2000-Serial|Advertisement):',
	'^X-Mailer: (Mail Bomber|Accucast)',

	# older Pegasus does this, but *lots* of spamware does too
	'^Comments: Authenticated sender is',

	# the law says you must tag, and my sanity says I must block
	'^Subject: ADV ?:',
)->set_message(
	'NO UCE means NO SPAM (no kidding!)'
);

my $virusbounce_headers = &HeaderRegex(
	'^Subject: MDaemon Warning - Virus Found',
	'^Subject: Norton AntiVirus detected a virus',
	'^Subject: Returned due to virus; was:',
	'^Subject: ScanMail Message:',
	'^Subject: VIRUS \(.*\) IN (MAIL FROM YOU|YOUR MAIL)',
	'^Subject: Virus detected$',
	'^Subject: Virus Detected by Network Associates',
	'^Subject: Warning: E-mail viruses detected',
)->set_message(
	'Antivirus bounces to forged senders are also spam.  Please turn off your antivirus bounce notification!'
);

##### Dynamic pool rDNS, with exceptions.
# 
# "Good" ISPs partition their dynamic pools into easy-to-identify
# subdomains.  But some don't, so here we go....

my $dynamic_rdns = new Mail::Milter::Chain(
	# Grrr.  I shouldn't have to do this.  GET REAL rDNS, PEOPLE!
	&ConnectRegex(
		'\.(biz\.rr\.com|knology\.net|netrox\.net|dq1sn\.easystreet\.com)$',
	)->accept_match(1),
	&ConnectMatchesHostname->set_message(
		'Dynamic pool:  Connecting hostname %H contains IP address %A.  If this mail has been rejected in error'
	),
)->accept_break(1);

##### Inner chain: main collection of checks
#
# As well as the more complicated checks above, I've added some
# simpler ones directly in-line below.
#

my $inner_chain = new Mail::Milter::Chain(
	$dynamic_rdns,
	&HeloUnqualified,
	&HeloRawLiteral,
	&HeaderFromMissing,
	$bad_headers,
	$spam_headers,
	$virusbounce_headers,
	&HeaderRegex('^Received:.*email\.bigpond\.com \(mshttpd\)')->set_message(
		'We do not accept Telstra/Bigpond webmail here due to severe abuse; please use your real e-mail account.'
	),
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
		envrcpt => sub {
			shift; # $ctx
			(shift =~ /^<?postmaster\@/i) ?
				SMFIS_ACCEPT : SMFIS_CONTINUE;
		},
	},
	&DeferToRCPT($rewritten_chain),
);
$outer_chain->accept_break(1);

##### The milter itself.
#
# I personally use Sendmail::PMilter under the covers, but I'm
# deliberately using the Sendmail::Milter API below to make this
# example work outside my installation.
#

Sendmail::Milter::auto_setconn('newmilter');
Sendmail::Milter::register('newmilter', $outer_chain, SMFI_CURR_ACTS);
Sendmail::Milter::main(10, 50);
