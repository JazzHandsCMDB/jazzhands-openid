#!/usr/local/bin/perl

use strict;
use warnings;

package OpenIDCode;

use strict;
use warnings;
use CGI;
use CGI::Carp   qw(fatalsToBrowser);
use Digest::SHA qw(sha256_hex);
use FileHandle;
use JSON;
use Crypt::PK::RSA;
use Crypt::JWT qw(encode_jwt decode_jwt);
use HTML::Tiny;
use Crypt::CBC;
use Crypt::Rijndael;
use MIME::Base64;
use JazzHands::DBI;
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
	my $h   = $args{h}   or die "h parameter is required";

	# Optional arguments
	my $key_path     = $args{key_path}     || '/www/auth/dance.key';
	my $clients_file = $args{clients_file} || '/www/auth/valid-clients.json';
	my $encrypt_password = $args{encrypt_password};
	my $debug            = $args{debug};

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
	$self->{h}            = $h;
	$self->{key}          = $key;
	$self->{key_path}     = $key_path;
	$self->{clients}      = $clients;
	$self->{clients_file} = $clients_file;
	$self->{debug}        = $debug;

	# Handle encrypt_password option
	if ($encrypt_password) {
		$self->{_encrypt_password} = $encrypt_password;
	} elsif ( my $a = $ENV{'JAZZHANDS_ENCRYPT_PASSWORD'} ) {
		if ( $a =~ /^(yes|true)$/i ) {
			$self->{_encrypt_password} = 1;
		} elsif ( $a !~ /^(no|false)$/i ) {
			die "Failed to configure password encryption.";
		}
	}

	return bless $self, $class;
}

# Method to validate client_id
sub validate_client {
	my ( $self, $params ) = @_;
	my $client_id = $params->{client_id};

	# Check if client_id exists in loaded clients
	# At the authorization endpoint, we only check if the client_id is registered
	# No client_secret validation here - that happens at the token endpoint
	return exists $self->{clients}->{$client_id};
}

# Method to generate login form HTML
sub generate_output_login_form {
	my ( $self, $params, $error_message ) = @_;
	my $cgi                   = $self->{cgi};
	my $h                     = $self->{h};
	my $response_type         = $params->{response_type};
	my $client_id             = $params->{client_id};
	my $redirect_uri          = $params->{redirect_uri};
	my $scope                 = $params->{scope};
	my $state                 = $params->{state};
	my $nonce                 = $params->{nonce};
	my $code_challenge        = $params->{code_challenge};
	my $code_challenge_method = $params->{code_challenge_method};

	# Build error div if there's an error message
	my @error_content = ();
	if ($error_message) {
		push @error_content,
		  $h->div( { class => 'error' },
			[ $h->strong( ['Error:'] ), ' ' . $error_message ] );
	}

	# Parse scope for display
	my @scopes      = split( /\s+/, $scope );
	my @scope_items = map { $h->li( [$_] ) } grep { $_ } @scopes;

	my $html = $h->html( [
		$h->head( [
			$h->title( ['OpenID Connect - Sign In'] ),
			$h->link( {
				rel  => 'stylesheet',
				type => 'text/css',
				href => '/login.css'
			} ),
			$h->script(
				{ type => 'text/javascript' },
				[ q{
function redirectToGSSAPI() {
	// Get the current pathname (e.g., /oauth/code)
	var currentPath = window.location.pathname;

	// Check if we're already on the negotiate path
	if (currentPath.indexOf('/negotiate/') === 0) {
		// Already on negotiate path, don't redirect
		return;
	}

	// Get the current origin (protocol + hostname + port)
	var origin = window.location.origin;
	// Build the negotiate endpoint URL
	var negotiateUrl = origin + '/negotiate/';

	// Try to fetch the negotiate endpoint
	fetch(negotiateUrl, {
		method: 'GET',
		credentials: 'include',
		redirect: 'manual'
	})
	.then(function(response) {
		// If the negotiate endpoint is accessible (status 200-399)
		if (response.ok || (response.status >= 200 && response.status < 400)) {
			// Build the new URL under /negotiate/
			var newUrl = origin + '/negotiate' + currentPath + window.location.search;
			// Redirect to the negotiate version of this page
			window.location.href = newUrl;
		} else {
			alert('GSSAPI/Kerberos endpoint not available');
		}
	})
	.catch(function(error) {
		// If there's an error (network error, CORS, etc.), show message
		console.log('Negotiate endpoint not available:', error);
		alert('GSSAPI/Kerberos endpoint not available');
	});
}
} ]
			)
		] ),
		$h->body( [
			$h->div(
				{ class => 'container' },
				[
					$h->div(
						{ class => 'header' },
						[
							$h->h1( { style => 'margin: 0;' }, ['🔐 Sign In'] ),
							$h->p(
								{ style => 'margin: 5px 0 0 0; opacity: 0.9;' },
								['OpenID Connect']
							)
						]
					),
					$h->div(
						{ class => 'content' },
						[
							@error_content,
							$h->div(
								{ class => 'info-box' },
								[
									$h->h3( ['APPLICATION REQUESTING ACCESS'] ),
									$h->p( [
										$h->strong( ['Client ID:'] ),
										' ',
										$h->code( [$client_id] )
									] ),
									$h->h3(
										{ style => 'margin-top: 15px;' },
										['REQUESTED PERMISSIONS']
									),
									$h->ul( [@scope_items] )
								]
							),
							$h->form(
								{ method => 'POST', action => '' },
								[
									$h->input( {
										type  => 'hidden',
										name  => 'response_type',
										value => $response_type
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'client_id',
										value => $client_id
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'redirect_uri',
										value => $redirect_uri
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'scope',
										value => $scope
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'state',
										value => $state
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'nonce',
										value => $nonce
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'code_challenge',
										value => $code_challenge
									} ),
									$h->input( {
										type  => 'hidden',
										name  => 'code_challenge_method',
										value => $code_challenge_method
									} ),
									$h->div(
										{ class => 'form-group' },
										[
											$h->label(
												{ for => 'username' },
												['Username']
											),
											$h->input( {
												type      => 'text',
												id        => 'username',
												name      => 'username',
												required  => 'required',
												autofocus => 'autofocus'
											} )
										]
									),
									$h->div(
										{ class => 'form-group' },
										[
											$h->label(
												{ for => 'password' },
												['Password']
											),
											$h->input( {
												type     => 'password',
												id       => 'password',
												name     => 'password',
												required => 'required'
											} )
										]
									),
									$h->div(
										{ class => 'button-group' },
										[
											$h->button( {
													type  => 'submit',
													name  => 'action',
													value => 'login',
													class => 'btn-primary'
												},
												['Sign In & Authorize']
											),
											$h->button( {
													type    => 'button',
													onclick =>
													  'redirectToGSSAPI()',
													class => 'btn-secondary'
												},
												['Use GSSAPI']
											)
										]
									)
								]
							)
						]
					)
				]
			)
		] )
	] );

	return "<!DOCTYPE html>\n" . $html;
}

# Method to authenticate user
sub authenticate_user {
	my ( $self, $params ) = @_;
	my $username = $params->{username};
	my $password = $params->{password};

	# Authenticate against database
	return 0 unless ( $username && $password );

	my $u = $self->get_account($username);
	return 0 unless $u;

	return $self->authenticate_account( $u, $password );
}

# Database connection method
sub dbh($) {
	my $self = shift @_;
	if ( !exists( $self->{_dbh} ) ) {
		my $dbh = JazzHands::DBI->connect(
			'jazzhands-oauth-jwt-minter',
			{ AutoCommit => 0, PrintError => 1 }
		);
		if ( !$dbh ) {
			die "Database connection failed: $JazzHands::DBI::errstr";
		}
		$self->{_dbh} = $dbh;
	}
	$self->{_dbh};
}

# Encrypt argument for database session
sub _db_session_encrypt_argument($$) {
	my $self     = shift;
	my $encodeme = shift;

	my $dbh = $self->dbh;

	# get a per-session key for encrypting arguments to the db
	my $sth = $dbh->prepare(
		qq{
			SELECT obfuscation_utils.get_session_secret();
        }
	) || die $dbh->errstr;
	$sth->execute || die $sth->errstr;
	my ($key) = $sth->fetchrow_array();
	$sth->finish;

	my $c  = Crypt::Rijndael->new($key);
	my $iv = Crypt::CBC->random_bytes(16);

	my $cipher = Crypt::CBC->new(
		-cipher => $c,
		-iv     => $iv,
		-header => 'none',
	);

	my $enc = $cipher->encrypt($encodeme);
	join( "-", encode_base64($iv), encode_base64($enc) );
}

# Get account from database
sub get_account($$) {
	my $self  = shift @_;
	my $login = shift @_;

	my $dbh = $self->dbh;

	my $sth = $dbh->prepare_cached(
		qq{
		SELECT	account_id, login, account_type
		FROM	account
		WHERE	login = ?
	}
	) || die "error setting up query";

	$sth->execute($login) || die "running account query";
	my $hr = $sth->fetchrow_hashref;
	$sth->finish;
	$hr;
}

# Authenticate account against database
sub authenticate_account($$$) {
	my $self        = shift @_;
	my $accounthash = shift @_;
	my $password    = shift @_;

	my $account_id = $accounthash->{account_id};

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached(
		q{
			SELECT account_password_manip.authenticate_account(
				account_id		:= :acid,
				password		:= :pwd,
				encode_method	:= :method,
				raiseexception	:= false
			);
        }
	) || die $dbh->errstr;

	$sth->bind_param( ':acid', $account_id ) || die $sth->errstr;
	if ( !$self->{_encrypt_password} ) {
		$sth->bind_param( ':pwd',    $password ) || die $sth->errstr;
		$sth->bind_param( ':method', 'none' )    || die $sth->errstr;
	} else {
		my $encryptedpw = $self->_db_session_encrypt_argument($password);
		$sth->bind_param( ':pwd',    $encryptedpw )       || die $sth->errstr;
		$sth->bind_param( ':method', 'aes-cbc/pad:pkcs' ) || die $sth->errstr;
	}

	if ( !( $sth->execute() ) ) {
		my $state = $dbh->state;
		my $msg   = $dbh->errstr;
		die "Temporary issues authenticating user: $msg";
	}

	my ($boolean) = $sth->fetchrow_array;
	$sth->finish;
	($boolean) ? 1 : 0;
}

# Method to generate session cookie
sub generate_session_cookie {
	my ( $self, $username ) = @_;

	# Use RSA key from object
	my $key = $self->{key};

	my $cookie_data = {
		'username' => $username,
		'expires'  => time() + ( 18 * 60 * 60 ),    # 18 hours from now
	};

	my $cookie_value = encode_jwt(
		payload       => $cookie_data,
		alg           => 'RSA-OAEP-256',
		key           => new Crypt::PK::RSA( \$key ),
		enc           => 'A256GCM',
		zip           => [ 'deflate', 9 ],
		serialization => 'compact',
	);

	return $cookie_value;
}

# Method to validate session cookie
# Returns: username on success, undef on error or no cookie (check errstr() to distinguish)
sub validate_session_cookie {
	my ($self) = @_;
	my $cgi = $self->{cgi};

	# Get the cookie
	my $cookie_value = $cgi->cookie('oauth_session');
	return undef unless $cookie_value;

	# Use RSA key from object
	my $key = $self->{key};

	# Try to decode the JWT
	my $decoded;
	eval {
		$decoded = decode_jwt(
			token => $cookie_value,
			key   => new Crypt::PK::RSA( \$key ),
		);
	};
	if ($@) {
		my $error = $@;
		$error =~ s/\n.*$//s;    # Keep only first line of error
		$self->ErrorF( "JWT decryption failed - %s", $error );
		return undef;
	}

	# The decoded JWT payload should be a hash reference
	unless ( ref($decoded) eq 'HASH' ) {
		$self->ErrorF("JWT payload is not a hash reference");
		return undef;
	}

	# Check for required fields
	unless ( $decoded->{username} ) {
		$self->ErrorF("Session cookie missing required username field");
		return undef;
	}

	# Check if expired
	if ( $decoded->{expires} && $decoded->{expires} < time() ) {
		return undef;    # Cookie expired (not an error, just expired)
	}

	# Return the username if valid
	return $decoded->{username};
}

# Method to generate authorization code
sub generate_authorization_code {
	my ( $self, $params ) = @_;
	my $client_id = $params->{client_id};
	my $username  = $params->{username};

	# Use RSA key from object
	# The code is actually an encrypted JWT; this should be stored in the database
	# rather than passed around as a token.
	my $key = $self->{key};

	my $h = {
		'username'              => $username,
		'scope'                 => $params->{scope},
		'client_id'             => $params->{client_id},
		'redirect_uri'          => $params->{redirect_uri},
		'expires'               => time() + 600,
		'nonce'                 => $params->{nonce},
		'code_challenge'        => $params->{code_challenge},
		'code_challenge_method' => $params->{code_challenge_method},
	};

	my $j    = new JSON;
	my $code = encode_jwt(
		payload       => $j->encode($h),
		alg           => 'RSA-OAEP-256',
		key           => new Crypt::PK::RSA( \$key ),
		enc           => 'A256GCM',
		zip           => [ 'deflate', 9 ],
		serialization => 'compact',
	);

	return $code;
}

# Method to generate already authenticated page HTML (SSO flow)
# If debug is not set, this returns undef to signal immediate redirect
sub generate_output_already_authenticated {
	my ( $self, $params, $username, $redirect_url ) = @_;
	my $cgi       = $self->{cgi};
	my $h         = $self->{h};
	my $client_id = $params->{client_id};
	my $scope     = $params->{scope};

	# If debug is not set, return undef to signal immediate redirect
	return undef unless ( $self->{debug} && $self->{debug} != 0 );

	my $html = $h->html( [
		$h->head( [
			$h->title( ['OpenID Connect'] ),
			$h->meta(
				{ 'http-equiv' => 'refresh', content => "3;url=$redirect_url" }
			),
			$h->link( {
				rel  => 'stylesheet',
				type => 'text/css',
				href => '/login.css'
			} )
		] ),
		$h->body( [
			$h->div(
				{ class => 'success' },
				[
					$h->h2( ['✓ Already Authenticated'] ),
					$h->p( [
						'Welcome back, ',
						$h->strong( [$username] ),
						'! You are already signed in.'
					] ),
					$h->div( { class => 'spinner' }, [] ),
					$h->p( ['Redirecting back to application...'] )
				]
			),
			$h->div(
				{ class => 'info' },
				[
					$h->h3( ['Authorization Details:'] ),
					$h->p( [
						$h->strong( ['User:'] ),
						' ',
						$h->code( [$username] )
					] ),
					$h->p( [
						$h->strong( ['Client ID:'] ),
						' ',
						$h->code( [$client_id] )
					] ),
					$h->p( [
						$h->strong( ['Scope:'] ), ' ', $h->code( [$scope] ) ] )
				]
			),
			$h->p(
				{ style => 'margin-top: 20px;' },
				[
					'If you are not redirected automatically, ',
					$h->a( { href => $redirect_url }, ['click here'] ),
					'.'
				]
			)
		] )
	] );

	return "<!DOCTYPE html>\n" . $html;
}

# Method to generate success page HTML
# If debug is not set, this returns undef to signal immediate redirect
sub generate_output_success_page {
	my ( $self, $params, $redirect_url, $code ) = @_;
	my $cgi          = $self->{cgi};
	my $h            = $self->{h};
	my $client_id    = $params->{client_id};
	my $redirect_uri = $params->{redirect_uri};
	my $scope        = $params->{scope};
	my $username     = $params->{username};

	# If debug is not set, return undef to signal immediate redirect
	return undef unless ( $self->{debug} && $self->{debug} != 0 );

	my $html = $h->html( [
		$h->head( [
			$h->title( ['OpenID Connect'] ),
			$h->meta(
				{ 'http-equiv' => 'refresh', content => "3;url=$redirect_url" }
			),
			$h->link( {
				rel  => 'stylesheet',
				type => 'text/css',
				href => '/login.css'
			} )
		] ),
		$h->body( [
			$h->div(
				{ class => 'success' },
				[
					$h->h2( ['✓ Authorization Successful'] ),
					$h->p( [ 'Welcome, ', $h->strong( [$username] ), '!' ] ),
					$h->div( { class => 'spinner' }, [] ),
					$h->p( ['Redirecting back to application...'] )
				]
			),
			$h->div(
				{ class => 'info' },
				[
					$h->h3( ['Authorization Details:'] ),
					$h->p( [
						$h->strong( ['User:'] ),
						' ',
						$h->code( [$username] )
					] ),
					$h->p( [
						$h->strong( ['Client ID:'] ),
						' ',
						$h->code( [$client_id] )
					] ),
					$h->p( [
						$h->strong( ['Redirect URI:'] ),
						' ',
						$h->code( [$redirect_uri] )
					] ),
					$h->p( [
						$h->strong( ['Scope:'] ), ' ', $h->code( [$scope] ) ] ),
					$h->p( [
						$h->strong( ['Authorization Code:'] ),
						' ', $h->code( [$code] )
					] )
				]
			),
			$h->p(
				{ style => 'margin-top: 20px;' },
				[
					'If you are not redirected automatically, ',
					$h->a( { href => $redirect_url }, ['click here'] ),
					'.'
				]
			)
		] )
	] );

	return "<!DOCTYPE html>\n" . $html;
}

# Method to generate authorization denial HTML
sub generate_output_denial {
	my ( $self, $params ) = @_;
	my $cgi          = $self->{cgi};
	my $h            = $self->{h};
	my $redirect_uri = $params->{redirect_uri};
	my $state        = $params->{state};

	if ($redirect_uri) {
		my $separator = ( $redirect_uri =~ /\?/ ) ? '&' : '?';
		my $error_url = $redirect_uri . $separator . "error=access_denied";
		$error_url .= "&error_description="
		  . $cgi->escape("The user denied the authorization request");
		$error_url .= "&state=" . $cgi->escape($state) if $state;

		my $html = $h->html( [
			$h->head( [
				$h->title( ['Authorization Denied'] ),
				$h->meta( {
					'http-equiv' => 'refresh',
					content      => "3;url=$error_url"
				} ),
				$h->link( {
					rel  => 'stylesheet',
					type => 'text/css',
					href => '/login.css'
				} )
			] ),
			$h->body( [
				$h->div(
					{ class => 'denied' },
					[
						$h->h2( ['❌ Authorization Denied'] ),
						$h->p( ['You have denied the authorization request.'] ),
						$h->p( ['Redirecting back to application...'] )
					]
				)
			] )
		] );

		return "<!DOCTYPE html>\n" . $html;
	}
	return '';
}

# Method to generate error response HTML
sub generate_output_error {
	my ( $self, $params, $error, $error_description ) = @_;
	my $cgi = $self->{cgi};
	my $h   = $self->{h};

	my $redirect_uri = $params->{redirect_uri};
	my $state        = $params->{state};

	# If redirect_uri is available, redirect with error
	if ($redirect_uri) {
		my $separator = ( $redirect_uri =~ /\?/ ) ? '&' : '?';
		my $error_url =
		  $redirect_uri . $separator . "error=" . $cgi->escape($error);
		$error_url .= "&error_description=" . $cgi->escape($error_description);
		$error_url .= "&state=" . $cgi->escape($state) if $state;

		my $html = $h->html( [
			$h->head( [
				$h->title( ['Authorization Error'] ),
				$h->meta( {
					'http-equiv' => 'refresh',
					content      => "3;url=$error_url"
				} ),
				$h->link( {
					rel  => 'stylesheet',
					type => 'text/css',
					href => '/login.css'
				} )
			] ),
			$h->body( [
				$h->div(
					{ class => 'error' },
					[
						$h->h2( ["Error: $error"] ),
						$h->p( [$error_description] ),
						$h->p( ['Redirecting back to application...'] )
					]
				)
			] )
		] );

		return "<!DOCTYPE html>\n" . $html;
	} else {

		# Display error page
		my $html = $h->html( [
			$h->head( [
				$h->title( ['Authorization Error'] ),
				$h->link( {
					rel  => 'stylesheet',
					type => 'text/css',
					href => '/login.css'
				} )
			] ),
			$h->body( [
				$h->div(
					{ class => 'error' },
					[
						$h->h2( ['Authorization Error'] ),
						$h->p( [ $h->strong( ['Error:'] ), ' ' . $error ] ),
						$h->p( [
							$h->strong( ['Description:'] ),
							' ' . $error_description
						] )
					]
				)
			] )
		] );

		return "<!DOCTYPE html>\n" . $html;
	}
}

# Cleanup database connection on object destruction
sub DESTROY {
	my $self = shift @_;

	if ( exists( $self->{_dbh} ) ) {
		$self->{_dbh}->rollback;
		$self->{_dbh}->disconnect;
		delete( $self->{_dbh} );
	}
}

1;

package main;

use strict;
use warnings;
use CGI;
use HTML::Tiny;

# Create CGI object
my $cgi = CGI->new;

# Create HTML::Tiny object
my $h = HTML::Tiny->new;

# Create OpenIDCode object
my $oidc = OpenIDCode->new(
	cgi => $cgi,
	h   => $h,
);
unless ($oidc) {
	print $cgi->header(
		-type    => 'text/html',
		-charset => 'utf-8',
		-status  => '500 Internal Server Error'
	);
	print "<h1>Error</h1><p>$OpenIDCode::errstr</p>";
	exit;
}

# Get parameters from the request and store in hash
my $params = {
	response_type         => $cgi->param('response_type')         || '',
	client_id             => $cgi->param('client_id')             || '',
	redirect_uri          => $cgi->param('redirect_uri')          || '',
	scope                 => $cgi->param('scope')                 || '',
	state                 => $cgi->param('state')                 || '',
	nonce                 => $cgi->param('nonce')                 || '',
	username              => $cgi->param('username')              || '',
	password              => $cgi->param('password')              || '',
	action                => $cgi->param('action')                || '',
	code_challenge        => $cgi->param('code_challenge')        || '',
	code_challenge_method => $cgi->param('code_challenge_method') || '',
};

# Variables to hold output and optional cookie
my $output;
my $cookie;

# Early validation: Check required parameters first
if (   !$params->{response_type}
	|| !$params->{client_id}
	|| !$params->{redirect_uri} )
{
	$output = $oidc->generate_output_error( $params, 'invalid_request',
		'Missing required parameters: response_type, client_id, and redirect_uri'
	);
}

# Early validation: Check response_type
elsif ( $params->{response_type} ne 'code' ) {
	$output =
	  $oidc->generate_output_error( $params, 'unsupported_response_type',
		'Only response_type=code is supported' );
}

# Early validation: Check if client_id is valid
elsif ( !$oidc->validate_client($params) ) {
	$output = $oidc->generate_output_error( $params, 'invalid_client',
		'Unknown or invalid client_id' );
}

# Check for GSS_NAME environment variable (Kerberos/SPNEGO authentication)
elsif ( !$params->{action} && $ENV{'GSS_NAME'} ) {
	my $remote_user = $ENV{'GSS_NAME'};

	# Strip off everything after @ sign if present
	$remote_user =~ s/@.*$//;

	# Look up the account
	my $account = $oidc->get_account($remote_user);

	if ($account) {

		# User is authenticated via GSS_NAME
		$params->{username} = $remote_user;

		# Generate session cookie
		my $cookie_value = $oidc->generate_session_cookie($remote_user);

		# Set both the session cookie and the favor_gssapi preference cookie
		my $gssapi_preference_cookie = $cgi->cookie(
			-name     => 'oauth_favor_gssapi',
			-value    => '1',
			-expires  => '+10y',
			-path     => '/',
			-secure   => 1,
			-httponly => 1,
			-samesite => 'Lax'
		);

		$cookie = [
			$cgi->cookie(
				-name     => 'oauth_session',
				-value    => $cookie_value,
				-expires  => '+18h',
				-path     => '/',
				-secure   => 1,
				-httponly => 1,
				-samesite => 'Lax'
			),
			$gssapi_preference_cookie
		];

		# Generate authorization code
		my $authorization_code = $oidc->generate_authorization_code($params);

		# Build redirect URL with authorization code
		my $separator = ( $params->{redirect_uri} =~ /\?/ ) ? '&' : '?';
		my $redirect_url =
			$params->{redirect_uri}
		  . $separator . "code="
		  . $cgi->escape($authorization_code);

		# Add state parameter if provided (REQUIRED for security)
		if ( $params->{state} ) {
			$redirect_url .= "&state=" . $cgi->escape( $params->{state} );
		}

		# Add nonce parameter if provided
		if ( $params->{nonce} ) {
			$redirect_url .= "&nonce=" . $cgi->escape( $params->{nonce} );
		}

		# Generate success page (or redirect if debug not set)
		$output = $oidc->generate_output_success_page( $params, $redirect_url,
			$authorization_code );

		# If output is undef (debug not set), redirect immediately
		if ( !defined $output ) {
			print $cgi->redirect(
				-uri    => $redirect_url,
				-status => 302,
				-cookie => $cookie
			);
			exit;
		}
	} else {

		# GSS_NAME is set but account not found - show error
		$output = $oidc->generate_output_error( $params, 'invalid_request',
			"Account '$remote_user' not found in system" );
	}
}

# Check for valid session cookie (before login form submission)
elsif ( !$params->{action} ) {
	my $cookie_username = $oidc->validate_session_cookie();

	# Check if cookie validation returned an error (not just expired/missing)
	if ( !defined $cookie_username && $oidc->errstr() ) {
		my $error_detail = $oidc->errstr();

		# Clear the invalid cookie
		$cookie = $cgi->cookie(
			-name     => 'oauth_session',
			-value    => '',
			-expires  => '-1d',
			-path     => '/',
			-secure   => 1,
			-httponly => 1,
			-samesite => 'Lax'
		);

		$output = $oidc->generate_output_error( $params, 'invalid_session',
			"Session validation failed: $error_detail" );
	} elsif ($cookie_username) {

		# User has valid session cookie, generate authorization code automatically
		$params->{username} = $cookie_username;
		my $authorization_code = $oidc->generate_authorization_code($params);

		# Build redirect URL with authorization code
		my $separator = ( $params->{redirect_uri} =~ /\?/ ) ? '&' : '?';
		my $redirect_url =
			$params->{redirect_uri}
		  . $separator . "code="
		  . $cgi->escape($authorization_code);

		# Add state parameter if provided
		if ( $params->{state} ) {
			$redirect_url .= "&state=" . $cgi->escape( $params->{state} );
		}

		# Add nonce parameter if provided
		if ( $params->{nonce} ) {
			$redirect_url .= "&nonce=" . $cgi->escape( $params->{nonce} );
		}

		$output = $oidc->generate_output_already_authenticated( $params,
			$cookie_username, $redirect_url );

		# If output is undef (debug not set), redirect immediately
		if ( !defined $output ) {
			print $cgi->redirect(
				-uri    => $redirect_url,
				-status => 302
			);
			exit;
		}
	} else {

		# No cookie or expired - check if user prefers GSSAPI
		my $favor_gssapi = $cgi->cookie('oauth_favor_gssapi');

		if ( $favor_gssapi && $favor_gssapi =~ /^(1|true|yes)$/i ) {

			# User prefers GSSAPI - redirect to /negotiate/ path
			# Build the negotiate URL dynamically
			my $request_uri = $ENV{'REQUEST_URI'} || '';
			my $scheme      = $ENV{'HTTPS'} ? 'https' : 'http';
			my $host        = $ENV{'HTTP_HOST'} || $ENV{'SERVER_NAME'};

			# Parse the current path from REQUEST_URI (strip query string)
			my $current_path = $request_uri;
			$current_path =~ s/\?.*$//;

			# Build the negotiate URL
			my $negotiate_url =
			  $scheme . '://' . $host . '/negotiate' . $current_path;

			# Add back the query string if present
			if ( $request_uri =~ /\?(.+)$/ ) {
				$negotiate_url .= '?' . $1;
			}

			# Redirect to the negotiate path
			print $cgi->redirect(
				-uri    => $negotiate_url,
				-status => 302
			);
			exit;
		} else {

			# Show login form
			$output = $oidc->generate_output_login_form( $params, '' );
		}
	}
}

# If user submitted the login form
elsif ($params->{action} eq 'login'
	&& $params->{username}
	&& $params->{password} )
{

	# Validate credentials (simplified - in production use proper authentication)
	if ( $oidc->authenticate_user($params) ) {

		# Generate session cookie
		my $cookie_value =
		  $oidc->generate_session_cookie( $params->{username} );
		$cookie = $cgi->cookie(
			-name     => 'oauth_session',
			-value    => $cookie_value,
			-expires  => '+18h',
			-path     => '/',
			-secure   => 1,
			-httponly => 1,
			-samesite => 'Lax'
		);

		# Generate authorization code
		my $authorization_code = $oidc->generate_authorization_code($params);

		# Build redirect URL with authorization code
		my $separator = ( $params->{redirect_uri} =~ /\?/ ) ? '&' : '?';
		my $redirect_url =
			$params->{redirect_uri}
		  . $separator . "code="
		  . $cgi->escape($authorization_code);

		# Add state parameter if provided (REQUIRED for security)
		if ( $params->{state} ) {
			$redirect_url .= "&state=" . $cgi->escape( $params->{state} );
		}

		# Add nonce parameter if provided
		if ( $params->{nonce} ) {
			$redirect_url .= "&nonce=" . $cgi->escape( $params->{nonce} );
		}

		# Generate success page
		$output = $oidc->generate_output_success_page( $params, $redirect_url,
			$authorization_code );

		# If output is undef (debug not set), redirect immediately
		if ( !defined $output ) {
			print $cgi->redirect(
				-uri    => $redirect_url,
				-cookie => $cookie,
				-status => 302
			);
			exit;
		}
	} else {

		# Authentication failed - show login form with error
		$output = $oidc->generate_output_login_form( $params,
			'Invalid username or password' );
	}
} elsif ( $params->{action} eq 'deny' ) {

	# User denied authorization
	$output = $oidc->generate_output_denial($params);
} else {

	# Show login form
	$output = $oidc->generate_output_login_form( $params, '' );
}

# Print header and output (single point of output for entire script)
if ($cookie) {
	print $cgi->header(
		-type    => 'text/html',
		-charset => 'utf-8',
		-cookie  => $cookie
	);
} else {
	print $cgi->header(
		-type    => 'text/html',
		-charset => 'utf-8'
	);
}
print $output;
