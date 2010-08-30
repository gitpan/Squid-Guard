package Squid::Guard;

use 5.008008;
use strict;
use warnings;

our @ISA = qw();

our $VERSION = '0.08';

use Carp;
use DB_File;
use Fcntl;
use Squid::Guard::Request;

=head1 NAME

Squid::Guard - Redirector for the Squid web proxy

=head1 SYNOPSYS

    use Squid::Guard;

    my $sg = Squid::Guard->new();

    $sg->redir("http://proxy/cgi-bin/deny.pl";);

    $sg->checkf(\&check);

    $sg->run;

=head1 DESCRIPTION

Squid::Guard is a module for creating a simple yet flexible
redirector for the Squid web cache engine.
This module was inspired by squidGuard, a popular squid redirector
written in C, but aims to be more flexible and in some ways simpler
to use.
I was happy with squidGuard and used it for years. But I needed
certain extra features like the ability to differentiate
between users based on some external program output, group
belongings etc.
squidGuard did not support this, so Squid::Guard was born.


=head2 Squid::Guard->new( opt => val, ...)

    API call to create a new server.  Does not actually start running anything until you call C<-E<gt>run()>.

=cut

sub new {
	my $class = shift;
	my %opts = @_;

	my $self  = {};

	$self->{dbdir}          = undef;
	$self->{forcedbupdate}  = 0;
	$self->{checkf}         = undef;
	$self->{categ}          = {};
	$self->{redir}          = ();
	$self->{strictauth}     = 0;
	$self->{verbose}        = 0;
	$self->{debug}          = 0;
	$self->{oneshot}        = 0;

	for( keys %opts ) {
		$self->{$_} = $opts{$_};
	}

	bless($self, $class);
	return $self;
}


=head2 $sg->redir()

    Get/set the redir page.
    The following macros are supported:

=over

=item %u	the requested url

=item %p	the path and the optional query string of %u, but note for convenience without the leading "/"

=item %a	the client IP address 

=item %n	the client FQDN

=item %i	the user name, if available

=item %t	the C<checkf> function result (see)

=item %%	the % sign

=back

    If set to the special value C<CHECKF>, then the return value of the checkf function, if true, is used directly as the redirection url

=cut

sub redir {
	my $self = shift;
	if (@_) { $self->{redir} = shift }
	return $self->{redir};
}


=head2 $sg->checkf()

    Sets the check callback function, which is called upn each request received.
    The check function receives as arguments the current C<Squid::Guard> object, and a L<Squid::Guard::Request> object on which the user can perform tests.
    A false return value means no redirection is to be proformed. A true return value means that the request is to be redirected to what was declared with C<redir()>.

=cut

sub checkf {
	my $self = shift;
	my $funcref = shift;
	$self->{checkf} = $funcref;
}


=head2 $sg->verbose()

    Get/set verbosity. Currently only one level of verbosity is supported

=cut

sub verbose {
	my $self = shift;
	if (@_) { $self->{verbose} = shift }
	return $self->{verbose};
}


=head2 $sg->debug()

    Emit debug info

=cut

sub debug {
	my $self = shift;
	if (@_) { $self->{debug} = shift }
	$self->{debug} and $self->{verbose} = $self->{debug};
	return $self->{debug};
}


=head2 $sg->oneshot()

    Executes only a single iteration then exits (can be used when debugging)

=cut

sub oneshot {
	my $self = shift;
	if (@_) { $self->{oneshot} = shift }
	return $self->{oneshot};
}


=head2 $sg->handle($req)

    Handles a request, returning the empty string or the redirected url.
    The request can be either a string in the format passed to the redirector by squid, or a Squid::Guard::Request object.
    This sub is usually called internally by run() to handle a request, but can be called directly too.

=cut

sub handle {
	my $self = shift;

	return "" unless $self->{checkf};

	my $arg = shift;
	my $req = ref($arg) ? $arg : Squid::Guard::Request->new($arg);

	my $redir = "";

	my $res = $self->{checkf}->( $self, $req );
	if( $res ) {
		if( $self->{redir} eq 'CHECKF' ) {
			$redir = $res;
		} else {
			$redir = $self->{redir} || croak "A request was submitted, but redir url is not defined";
			$redir =~ s/(?<!%)%a/$req->addr/ge;
			$redir =~ s/(?<!%)%n/$req->fqdn or "unknown"/ge;
			$redir =~ s/(?<!%)%i/$req->ident or "unknown"/ge;
			#$redir =~ s/(?<!%)%s//;	# Contrary to squidGuard, it does not mean anything to us
			$redir =~ s/(?<!%)%u/$req->url/ge;
			my $pq = $req->path_query;
			$pq =~ s-^/--o;
			$redir =~ s/(?<!%)%p/$pq/g;
			$redir =~ s/(?<!%)%t/$res/ge;
			$redir =~ s/%%/%/;

# Redirections seem not to be understood when the request was for HTTPS.
# Info taken from http://www.mail-archive.com/squid-users@squid-cache.org/msg58422.html :
# Squid is a little awkward:
# the URL returned by squidguard must have the protocol as the original URL.
# So for a URL with HTTPS protocol, squidguard must return a URL that uses the HTTPS protocol.
# This is really not nice but the workaround is to use a 302 redirection:
#   redirect        302:http://www.internal-server.com/blocked.html

# another one on the issue: http://www.techienuggets.com/Comments?tx=114527
# Blocking/filtering SSL pages with SquidGuard do not work very well. You
# need to use Squid acls for that, or wrap up SquidGuard as an external
# acl instead of url rewriter..
#
# The reason is that
# a) Most browsers will not accept a browser redirect in response to
# CONNECT.
#
# b) You can't rewrite a CONNECT request into a http:// requrest.
#
# c) Most browsers will be quite upset if you rewrite the CONNECT to a
# different host than requested.
#
# meaning that there is not much you actually can do with CONNECT requests
# in SquidGuard that won't make browsers upset.

# So let's redirect.
# Maybe we should check if $url begins with http:// .

			if( $req->method eq 'CONNECT' ) {
				$redir = "302:$redir";
			}
		}
	}

	return $redir;
}


=head2 $sg->run()

    Starts handling the requests, reading them from <STDIN> one per line in the format used by Squid to talk to the url_rewrite_program

=cut

sub run {
        my $self = shift;

	$self->{redir} || croak "Can not run when redir url is not defined";

	$|=1;   # force a flush after every print on STDOUT

	while (<STDIN>) {

		chomp;
		$self->{verbose} and print STDERR "Examining $_\n";

		my $redir = $self->handle($_);

		if( $redir ) {
			$self->{verbose} and print STDERR "Returning $redir\n";
			print "$redir\n";
		} else {
			print "\n";
		}

		last if $self->{oneshot};
	}
}


=head2 Black/white-list support

Squid::Guard provides support for using precompiled black or white lists, in a way similar to what squidGuard does. These lists are organized in categories. Each category has its own path (a directory) where three files can reside. These files are named domains, urls and expressions. There's no need for all three to be there, and in most situations only the domains and urls files are used. These files list domains, urls and/or (regular) expressions which describe if a request belong to the category. You can decide, in the checkf function, to allow or to redirect a request belonging to a certain category.
Similarly to what squidGuard does, the domains and urls files have to be compiled in .db form prior to be used. This makes it possible to run huge domains and urls lists, with acceptable performance.
You can find precompiled lists on the net, or create your own.

=head2 $sg->dbdir()

    Get/set dbdir parameter, i.e. the directory where category subdirs are found. .db files generated from domains and urls files will reside here too.

=cut

sub dbdir {
	my $self = shift;
	if (@_) { $self->{dbdir} = shift }
	return $self->{dbdir};
}


=head2 $sg->addcateg( name => path, ... )

    Adds one or more categories.
    C<path> is the directory, relative to dbdir, containing the C<domains>, C<urls> and C<expressions> files.

=cut

sub addcateg {
	my $self = shift;
	my %h = ( @_ );
	foreach my $cat (keys %h) {
		$self->{categ}->{$cat}->{loc} = $h{$cat};

		my $l = $self->{dbdir} . '/' . $self->{categ}->{$cat}->{loc};
		#print STDERR "$l\n";

		my $domsrc = "${l}/domains";
		my $domdb = "${domsrc}.db";
		if( -f $domsrc ) {
			# tie .db for reading
			my %h;
			my $X = tie (%h, 'DB_File', $domdb, O_RDONLY, 0644, $DB_BTREE) || croak ("Cannot open $domdb: $!");
			$self->{categ}->{$cat}->{d} = \%h;
			$self->{categ}->{$cat}->{dX} = $X;
		}

		my $urlsrc = "${l}/urls";
		my $urldb = "${urlsrc}.db";
		if( -f $urlsrc ) {
			# tie .db for reading
			my %h;
			my $X = tie (%h, 'DB_File', $urldb, O_RDONLY, 0644, $DB_BTREE) || croak ("Cannot open $urldb: $!");
			$self->{categ}->{$cat}->{u} = \%h;
			$self->{categ}->{$cat}->{uX} = $X;
		}

		my $e = "$l/expressions";
		if( -f $e ) {
			my @a;
			open( E, "< $e" ) or croak "Cannot open $e: $!";
			while( <E> ) {
				chomp;
				s/#.*//o;
				next if /^\s*$/o;
				push @a, qr/$_/i;	# array of regexps. Can't use 'o' regexp option, since I would put in the array always the same regexp (the first one). But it seems that with qr, 'o' is obsolete.
			}
			close E;
			$self->{categ}->{$cat}->{e} = \@a;
		}

	}
	return 1;
}


=head2 $sg->mkdb( name => path, ... )

    Creates/updates the .db files for the categories.
    Will search in C<path> for the potential presence of the C<domains> and C<urls> plaintext files.
    According to the value of the C<forcedbupdate> flag (see), will create or update the .db file from them.

=cut

sub mkdb {
	my $self = shift;
	my %h = ( @_ );
	foreach my $cat (keys %h) {
		$self->{categ}->{$cat}->{loc} = $h{$cat};

		my $l = $self->{dbdir} . '/' . $self->{categ}->{$cat}->{loc};
		#print STDERR "$l\n";

		my $domsrc = "${l}/domains";
		my $domdb = "${domsrc}.db";
		if( -f $domsrc ) {
			# update .db, if needed
			if( $self->{forcedbupdate} || (stat($domsrc))[9] > ( (stat($domdb))[9] || 0 ) ) {
				$self->{verbose} and print STDERR "Making $domdb\n";
				my %h;
				my $X = tie (%h, 'DB_File', $domdb, O_CREAT|O_TRUNC, 0644, $DB_BTREE) || croak ("Cannot create $domdb: $!");
				open( F, "< $domsrc") or croak "Cannot open $domsrc";
				while( <F> ) {
					chomp;
					s/#.*//o;
					next if /^\s*$/o;
					$h{lc($_)} = undef;
				}
				close F;
				undef $X;
				untie %h;
			} else {
				$self->{verbose} and print STDERR "$domdb more recent than $domsrc, skipped\n";
			}
		}

		my $urlsrc = "${l}/urls";
		my $urldb = "${urlsrc}.db";
		if( -f $urlsrc ) {
			# update .db, if needed
			if( $self->{forcedbupdate} || (stat($urlsrc))[9] > ( (stat($urldb))[9] || 0 ) ) {
				$self->{verbose} and print STDERR "Making $urldb\n";
				my %h;
				my $X = tie (%h, 'DB_File', $urldb, O_CREAT|O_TRUNC, 0644, $DB_BTREE) || croak ("Cannot create $urldb: $!");
				open( F, "< $urlsrc") or croak "Cannot open $urlsrc";
				while( <F> ) {
					chomp;
					s/#.*//o;
					next if /^\s*$/o;
					$h{lc($_)} = undef;
				}
				close F;
				undef $X;
				untie %h;
			} else {
				$self->{verbose} and print STDERR "$urldb more recent than $urlsrc, skipped\n";
			}
		}
	}
	return 1;
}


=head2 $sg->forcedbupdate()

    Controls whether mkdb should forcibly update the .db files.
    If set to a false value (which is the default), existing .db files are refreshed only if older than the respective plaintext file.
    If set to a true value, .db files are always (re)created.

=cut

sub forcedbupdate {
	my $self = shift;
	if (@_) { $self->{forcedbupdate} = shift }
	return $self->{forcedbupdate};
}


#=head2 $sg->getcateg()
#
#Gets the defined categories
#
#=cut
#
#sub getcateg {
#	my $self = shift;
#	my %h;
#	for( keys %{$self->{categ}} ) {
#		$h{$_} = $self->{categ}->{$_}->{loc};
#	}
#	return %h;
#}


# =head2 $sg->_domains()
# 
# Finds the super-domains where the given domain is nested.
# This is a helper sub for C<checkincateg>
# 
# =cut

sub _domains($) {
	my $host = shift;
	return () unless $host;
	# www . iotti . biz
	#  0      1      2
	my @a = split(/\./, $host);
	my $num = $#a;
	my @b;
	for( 0 .. $num ) {
		my $j = $num - $_;
		push @b, join(".", @a[$j .. $num]);
	}
	return @b;
}


# =head2 $sg->_uris()
# 
# Finds the uris containing the given uri.
# This is a helper sub for C<checkincateg>
# 
# =cut

sub _uris($) {
	my $uri = shift;
	return () unless $uri;
	# www.iotti.biz / dir1 / dir2 / dir3 / file
	#       0          1      2      3      4
	my @a = split(/\//, $uri);
	my $num = $#a;
	my @b;
	for( 0 .. $num ) {
		my $sub_uri = join("/", @a[0 .. $_]);
		push @b, $sub_uri;
		push @b, $sub_uri . '/' if $_ < $num;	# check www.iotti.biz/dir/ too (with the trailing slashe) since some publicly-available lists carry urls with trailing slashes
	}
	return @b;
}


=head2 $sg->checkincateg($req, $categ)

    Checks if a request is in a category

=cut

sub checkincateg($$$) {
	my ( $self, $req, $categ ) = @_;

	my $catref = $self->{categ};
	defined( $catref->{$categ} ) or croak "The requested category $categ does not exist";

	#print STDERR "s $req->scheme h $req->host p $req->path\n";
	if( defined( $catref->{$categ}->{d} ) ) {
		$self->{debug} and print STDERR " Check " . $req->host . " in $categ domains\n";
		my $ref = $catref->{$categ}->{d};
		foreach( _domains($req->host) ) {
			$self->{debug} and print STDERR "  Check $_\n";
			if(exists($ref->{$_})) {
				$self->{debug} and print STDERR "   FOUND\n";
				return 1;
			}
		}
	}
	if( defined( $catref->{$categ}->{u} ) ) {
		# in url checking, we test the authority part + the optional path part + the optional query part
		my $what = $req->authority_path_query;
		$self->{debug} and print STDERR " Check $what in $categ urls\n";
		my $ref = $catref->{$categ}->{u};
		foreach( _uris($what) ) {
			$self->{debug} and print STDERR "  Check $_\n";
			if(exists($ref->{$_})) {
				$self->{debug} and print STDERR "   FOUND\n";
				return 1;
			}
		}
	}
	if( defined( $catref->{$categ}->{e} ) ) {
		my $what = $req->url;
		$self->{debug} and print STDERR " Check $what in $categ expressions\n";
		my $ref = $catref->{$categ}->{e};
		foreach( @$ref ) {
			$self->{debug} and print STDERR "  Check $_\n";
			if( $what =~ /$_/i ) {	# Can't use 'o' regexp option, since I would compare always the same regexp.
				$self->{debug} and print STDERR "   FOUND\n";
				return 1;
			}
		}
	}
	return 0;
}


=head2 Other help subs that can be used in the checkf function


=head2 $sg->checkingroup($user, $group)

    Checks if a user is in a UNIX grop

=cut

sub checkingroup($$$) {
	my ( $self, $user, $group ) = @_;

	return 0 unless $user;

	my @pwent = getpwnam($user);
	if( ! @pwent ) {
		print STDERR "Can not find user $user\n";
		return 0;
	}

	my $uid      = $pwent[2];
	my $uprimgid = $pwent[3];
	if( ! defined $uid || ! defined $uprimgid ) {
		print STDERR "Can not find uid and gid corresponding to $user\n";
		return 0;
	}

	my @grent = getgrnam($group);
	if( ! @grent ) {
		print STDERR "Can not find group $group\n";
		return 0;
	}

	my $gid = $grent[2];
	if( ! defined $gid ) {
		print STDERR "Can not find gid corresponding to $group\n";
		return 0;
	}

	if( $uprimgid == $gid ) {
		$self->{debug} and print STDERR "FOUND $user has primary group $group\n";
		return 1;
	}

	my @membri = split(/\s+/, $grent[3]);
	$self->{debug} and print STDERR "Group $group contains:\n" . join("\n", @membri) . "\n";
	for(@membri) {
		my @pwent2 = getpwnam($_);
		my $uid2 = $pwent2[2];
		if( ! defined $uid2 ) {
			print STDERR "Can not find uid corresponding to $_\n";
			next;
		}
		if( $uid2 == $uid ) {
			$self->{debug} and print STDERR "FOUND $user is in $group\n";
			return 1;
		}
	}

	return 0;
}


=head2 $sg->checkinwbgroup($user, $group)

    Checks if a user is in a WinBind grop

=cut

sub checkinwbgroup($$$) {
	my ( $self, $user, $group ) = @_;

	return 0 unless $user;

	my $userSID = `wbinfo -n "$user"`;
	if( $? ) {
		print STDERR "Can not find user $user in winbind\n";
		return 0;
	}
	$userSID =~ s/\s.*//o;
	chomp $userSID;
	$self->{debug} and print STDERR "Found user $user with SID $userSID\n";

	my $groupSID = `wbinfo -n "$group"`;
	if( $? ) {
		print STDERR "Can not find group $group in winbind\n";
		return 0;
	}
	$groupSID =~ s/\s.*//o;
	chomp $groupSID;
	$self->{debug} and print STDERR "Found group $group with SID $groupSID\n";

	my @groupsSIDs = `wbinfo --user-domgroups "$userSID"`;
	if( $? ) {
		print STDERR "Can not find the SIDs of the groups of $user - $userSID\n";
		return 0;
	}
	$self->{debug} and print STDERR "$user is in the following groups:\n @groupsSIDs";

	foreach ( @groupsSIDs ) {
		chomp;
		if ( $_ eq $groupSID ) {
			$self->{debug} and print STDERR "   FOUND\n";
			return 1;
		}
	}

	return 0;
}


=head2 $sg->checkinaddr($req)

    Checks if a request is for an explicit IP address

=cut

sub checkinaddr($$) {
        my ( $self, $req ) = @_;
	# TODO: Maybe the test should be more accurate and more general
	return 1 if $req->host =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/o;
	return 0;
}


1;

__END__

=head1 AUTHOR

Luigi Iotti, E<lt>luigi@iotti.biz<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Luigi Iotti

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
