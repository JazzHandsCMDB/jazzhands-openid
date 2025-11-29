#!/usr/local/bin/perl

use warnings;
use strict;

package OpenIDToken;

use warnings;
use strict;
use CGI;
use Crypt::PK::RSA;
use Crypt::JWT qw(encode_jwt decode_jwt);
use JSON;
use FileHandle;
use Data::Dumper;
use LWP::Protocol::https;
use LWP::UserAgent;
use LWP::Debug        qw(+);
use Digest::SHA       qw(sha256_base64);
use JazzHands::Common qw(:internal);

use parent 'JazzHands::Common';

# Constructor
sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my %args  = @_;

	# Call parent constructor
	my $self = $class->SUPER::new();

	# Required arguments
	my $cgi = $args{cgi} or die "cgi parameter is required";

	# Optional arguments
	my $key_path     = $args{key_path}     || '/www/auth/dance.key';
	my $clients_file = $args{clients_file} || '/www/auth/valid-clients.json';

	# Load RSA key
	my $fh = new FileHandle($key_path);
	unless ($fh) {
		$errstr = "Unable to open key file: $key_path";
		return undef;
	}
	my $key = join( "", $fh->getlines() );
	$fh->close;

	# Load valid clients from JSON file
	my $clients_fh = new FileHandle($clients_file);
	unless ($clients_fh) {
		$errstr = "Unable to open clients file: $clients_file";
		return undef;
	}
	my $clients_json = join( "", $clients_fh->getlines() );
	$clients_fh->close;

	my $j = new JSON;
	my $clients;
	eval { $clients = $j->decode($clients_json); };
	if ($@) {
		$errstr = "Failed to parse clients file: $@";
		return undef;
	}

	$self->{cgi}          = $cgi;
	$self->{key}          = $key;
	$self->{key_path}     = $key_path;
	$self->{clients}      = $clients;
	$self->{clients_file} = $clients_file;

	return bless $self, $class;
}

# Subroutine to verify PKCE code challenge
# Returns: 1 on success, 0 on failure (also prints error and exits on failure)
sub verify_pkce {
	my ( $self, $code_challenge, $code_challenge_method, $code_verifier ) = @_;

	my $cgi = $self->{cgi};
	my $j   = new JSON;

	# Helper function to print error and exit
	my $print_error = sub {
		my ($error_desc) = @_;
		warn "++ printing error $error_desc";
		print $cgi->header(
			-status => '400 Bad Request',
			-type   => 'application/json',
		);
		my $error_response = $j->encode( {
			error             => 'invalid_grant',
			error_description => $error_desc
		} );
		print $error_response, "\n";
		exit 0;
	};

	if ( !$code_challenge || $code_challenge eq '' ) {

		# legacy code, no challenge
		return 1;
	}

	# Validate code_challenge_method
	unless ( $code_challenge_method eq 'S256'
		|| $code_challenge_method eq 'plain' )
	{
		$print_error->(
			"Invalid code_challenge_method '$code_challenge_method'. Must be either 'S256' or 'plain'"
		);
	}

	# Validate code_verifier format (RFC 7636 Section 4.1)
	my $verifier_length = length($code_verifier);

	if ( $verifier_length < 43 ) {
		$print_error->(
			"Code verifier too short (minimum 43 characters, got $verifier_length)"
		);
	} elsif ( $verifier_length > 128 ) {
		$print_error->(
			"Code verifier too long (maximum 128 characters, got $verifier_length)"
		);
	}

	# Check if verifier contains only allowed characters
	if ( $code_verifier !~ /^[A-Za-z0-9\-._~]+$/ ) {
		$print_error->(
			"Code verifier contains invalid characters. Allowed: A-Z, a-z, 0-9, -, ., _, ~"
		);
	}

	# Compute challenge based on method
	my $computed_challenge;

	if ( $code_challenge_method eq 'plain' ) {
		$computed_challenge = $code_verifier;
	} elsif ( $code_challenge_method eq 'S256' ) {

		# Compute SHA-256 hash of the verifier
		my $sha256_hash = sha256_base64($code_verifier);

		# Convert to base64url encoding
		# base64url encoding differs from base64: uses - instead of +, _ instead of /, and no padding
		$sha256_hash =~ tr/+/-/;
		$sha256_hash =~ tr/\//_/;
		$sha256_hash =~ s/=+$//;    # Remove padding

		$computed_challenge = $sha256_hash;
	}

	# Compare the challenges
	if ( $code_challenge eq $computed_challenge ) {
		return 1;                   # Verification successful
	} else {
		$print_error->("The code_verifier does not match the code_challenge");
	}
}

sub validate_client {
	my ( $self, $params ) = @_;
	my $client_id     = $params->{client_id};
	my $client_secret = $params->{client_secret};

	# Check if client_id exists and secret matches
	if ( exists $self->{clients}->{$client_id}
		&& $self->{clients}->{$client_id} eq $client_secret )
	{
		return 1;
	} else {
		warn "client $client_id and $client_secret do not match";
		return undef;
	}
}

sub printenv {

	# print "Content-type: text/plain; charset=iso-8859-1\n\n";
	foreach my $var ( sort( keys(%ENV) ) ) {
		my $val = $ENV{$var};
		$val =~ s|\n|\\n|g;
		$val =~ s|"|\\"|g;
		print STDERR "${var}=\"${val}\"\n";
	}
}

sub handle_token_request {
	my ($self) = @_;

	my $cgi = $self->{cgi};

	#
	# get token, state, issue an access token JWT...
	#
	my $params = {
		'grant_type'    => scalar $cgi->param('grant_type'),
		'code'          => scalar $cgi->param('code'),
		'code_verifier' => scalar $cgi->param('code_verifier'),    # XXX
		'client_id'     => scalar $cgi->param('client_id'),
		'client_secret' => scalar $cgi->param('client_secret'),
	};

	my $grant_type   = $params->{'grant_type'};
	my $code         = $params->{'code'};
	my $redirect_uri = $params->{'redirect_uri'};

	if ( !$self->validate_client($params) ) {
		print $cgi->header(
			-status => '400 Bad Request',
			-type   => 'application/json',
		);
		my $j = new JSON;
		my $p = $j->encode( {
				"error"           => 'invalid_client',
				error_description => "invalid_client"
			}
		);
		print $p, "\n";
		exit 0;
	}

	if ( $grant_type eq 'authorization_code' ) {

		#- printenv();
		#- my %headers = map { $_ => $cgi->http($_) } $cgi->http();
		#- warn Dumper(\%headers);
		# warn Dumper($cgi->Vars());
		#	warn "checking...\n";
		#       if(!$cgi->remote_user() ) {
		#               # print $cgi->header(-status=>'401', 'WWW-Authenticate' => 'Basic realm="Bite Me"');
		#	print "Status: 401 Unauthorized\n";
		#	print 'WWW-Authenticate: Basic realm="Realm", charset="UTF-8"', "\n";
		#	print 'Content-Type: text/html; charset=ISO-8859-1', "\n\n";
		#               exit(0);
		#       }
		#   printenv();
		my $key = $self->{key};

		# the code is actually all the details for authenticating the user. This should
		# probably be in a database, but meh.
		my $decode = decode_jwt(
			ignore_signature => 1,
			token            => $code,
			key              => Crypt::PK::RSA->new( \$key ),
		) || die "$!";

		# Call the verification function; prints an error and exists on failure. rethink?
		$self->verify_pkce(
			$decode->{code_challenge},
			$decode->{code_challenge_method},
			$params->{code_verifier}
		);

		if ( $decode->{expires} < time() ) {
			print $cgi->header(
				-status => '400 Bad Request',
				-type   => 'application/json',
			);
			my $j = new JSON;
			my $p = $j->encode( {
				"error"           => 'invalid_grant',
				error_description => "The code is invalid"
			} );
			print $p, "\n";
			exit 0;
		}

		my $oid = $decode->{username};

		my $acctok = {
			'aud' => $decode->{scope},
			'sub' => $oid,
			'jti' => '951649EB-CB6D-4A25-83C0-CDC9EF627FFF',
			'exp' => time + 86400,
		};
		my $bearer = encode_jwt(
			payload => $acctok,
			alg     => 'RS256',
			key     => Crypt::PK::RSA->new( \$key ),
		);

		my $idtok = {
			'aud'         => $decode->{client_id},
			'sub'         => $oid,
			'iss'         => 'https://oauth0.iad1.omniscient.com',
			'name'        => 'your mom',
			'given_name'  => 'your',
			'family_name' => 'mom',
			'jti'         => '951649EB-CB6D-4A25-83C0-CDC9EF627FFF',
			'exp'         => time() + 86400,
			'nbf'         => time(),
			'iat'         => time(),
			'nonce'       => $decode->{nonce},
		};
		my $idtoken = encode_jwt(
			payload => $idtok,
			alg     => 'RS256',
			key     => Crypt::PK::RSA->new( \$key ),
		);

		my $rv = {
			token_type   => 'Bearer',
			access_token => $bearer,
			id_token     => $idtoken,
			scope        => $decode->{scope},
			expires_in   => 3600,
		};

		my $j = new JSON;
		my $p = $j->encode($rv);
		print $cgi->header( -type => 'application/json', );
		print $p, "\n";
	} else {
		print $cgi->header(
			-status => '400 Bad Request',
			-type   => 'application/json',
		);
		my $j = new JSON;
		my $p = $j->encode( {
			"error"           => 'invalid_grant_type',
			error_description => "$grant_type is invalid"
		} );
		print $p, "\n";
		exit 0;
	}
}

1;

package main;

use strict;
use warnings;
use CGI;

# Create CGI object
my $cgi = CGI->new;

# Create OpenIDToken object
my $token = OpenIDToken->new( cgi => $cgi, );
unless ($token) {
	print $cgi->header(
		-type    => 'text/html',
		-charset => 'utf-8',
		-status  => '500 Internal Server Error'
	);
	print "<h1>Error</h1><p>$OpenIDToken::errstr</p>";
	exit;
}

# Handle the token request
$token->handle_token_request();
