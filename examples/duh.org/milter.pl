#!/usr/local/bin/perl -w -I../lib
# $Id: milter.pl,v 1.1 2004/02/25 16:29:05 tvierling Exp $
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

##### Connecting host regexes
#
# "Good" ISPs partition their dynamic pools into easy-to-identify
# subdomains.  But some don't, so here we go....
#

my $dynamic_regexes = &ConnectRegex(
	# specifics
	'^[^\.]+\.(?:elisa\.omakaista\.fi|\w\w\.hsia\.telus\.net)$',
	'^[\d-]+\.(?:cpe\.cableone\.net|mtnns\.net|brutele\.be|barak\.net\.il|bbeyond\.nl)$',
	'^[\d-]+\.cable\.\w+\.\w\w\.blueyonder\.co\.uk$',
	'^a[\d-]+\.xs4all\.nl$',
	'^adsl-[\d-]+\.dsl\.\w+\.(ameritech\.net|pacbell\.net)$',
	'^c[\d\.]+\.\w+\.\w\w\.charter\.com$',
	'^cpe-[\d-]+\.\w+\.(\w\w\.charter\.com|rr\.com)$',
	'^cs[\d-]+\.\w+\.rr\.com$',
	'^d[\d-]+\.cust\.tele2\.fr$',
	'^dclient.*\.hispeed\.ch$',
	'^dsl-[\d-]+\.(arcor-ip\.net|prodigy\.net\.mx)$',
	'^h[\d-]+\.\w+\.shawcable\.net$',
	'^host\d+\.\w+\.dsl\.primus\.ca$',
	'^ip[\d-]+\.\w\w\.\w\w\.cox\.net$',
	'^ip-[\d-]+\.internet\.co\.nz',
	'^pns[\d-]+\.inter\.net\.il$',
	'^public.*\.broadband\.ntl\.com$',
	'^user-\w+\.cable\.mindspring\.com$',

	# generics
	'^(?:dhcp|pool|ppp(?:oe)?)(?:-)?[\d-]+\.',
)->set_message(
	'Access denied to %H: This is a dynamic pool address; you must use your Internet provider\'s SMTP server for sending outbound mail'
);

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

##### Inner chain: main collection of checks
#
# As well as the more complicated checks above, I've added some
# simpler ones directly in-line below.
#

my $inner_chain = new Mail::Milter::Chain(
	$dynamic_regexes,
	&HeloUnqualified,
	&HeloRawLiteral,
	&HeaderFromMissing,
	$bad_headers,
	$spam_headers,
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

my $outer_chain = new Mail::Milter::Chain(
	&ConnectRegex(qw{
		^\[127\.
	})->accept_match(1),
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
Sendmail::Milter::main();
