# $Id: Milter.pm,v 1.24 2004/11/25 21:36:49 tvierling Exp $
#
# Copyright (c) 2002-2004 Todd Vierling <tv@pobox.com> <tv@duh.org>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the author nor the names of contributors may be used
# to endorse or promote products derived from this software without specific
# prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

package Mail::Milter;

use 5.006;

use strict;
use warnings;

use Carp;
use Symbol;
use UNIVERSAL;

our $VERSION = '0.06';

# internal function to resolve a callback from name to coderef
sub resolve_callback ($$) {
	my $cb = shift;
	my $pkg = shift;

	unless (UNIVERSAL::isa($cb, 'CODE')) {   
		my $cbref = qualify_to_ref($cb, $pkg);
		croak "callback points to nonexistent sub ${pkg}::${cb}" unless exists(&$cbref);

		$cb = \&$cb;
	}

	$cb;
}

1;
__END__

=pod

=head1 NAME

Mail::Milter - Perl extension modules for mail filtering via milter

=head1 SEE ALSO

L<Mail::Milter::Chain>

L<Mail::Milter::ContextWrapper>

L<Mail::Milter::Object>

L<Mail::Milter::Wrapper>

the Mail::Milter::Module::* manpages -- these include:
 * ConnectASNBL
 * ConnectDNSBL
 * ConnectMatchesHostname
 * ConnectRegex
 * HeaderFromMissing
 * HeaderRegex
 * HeloRawLiteral
 * HeloRegex
 * HeloUnqualified
 * MailDomainDNSBL
 * MailDomainDotMX
 * VirusBounceSpew

the Mail::Milter::Wrapper::* manpages -- these include:
 * DecodeSRS
 * DeferToRCPT
 * RejectMsgEditor

=cut
