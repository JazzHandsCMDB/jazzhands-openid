#!/usr/bin/env perl
#
# Copyright (c) 2021-2023 Todd Kover
# All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package worker;
use warnings;
use strict;
use Crypt::CBC;
use Crypt::PK::RSA;
use Crypt::JWT qw(encode_jwt);
use Crypt::Rijndael;
use MIME::Base64;
use JazzHands::DBI;
use CGI;
use Data::Dumper;
use FileHandle;
use JSON;
use utf8;
use UUID qw(uuid);
use Sys::Hostname;
use JazzHands::AppAuthAL qw(:parse :cache);
use JazzHands::Common qw(:log :internal);

use parent 'JazzHands::Common';

# All the values that can come out in the JWT
#
# {
#	"ist" : epoch,							# when issued, always
#	"sub" : "who to log",					# subject, humans, always
#	"jti" : "UUID",							# correlate to logs, always
#	"act" : {								# only if issued on behalf
#		"sub" : "kovert"					# who asked for it
#	},
#	"aud" : "URL",							# scope/audience, URL, always
#	"role" : "who to become",				# postgrest assumes this, always
#	"iss" : "4b3a867cabeb_oauthminter",		# where it was issued, always
#	"exp" : epoch,							# when expired, always
#	"nbf" : epoch							# when issued, always
# }

# optional, only if needed
eval "require JazzHands::Vault";

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self  = $class->SUPER::new(@_);
	bless $self, $class;

	my $opt = _options(@_);
	if ( defined( my $logfn = $opt->{log_config_filename} ) ) {
		if ( defined( my $fh = new FileHandle($logfn) ) ) {
			my $j    = new JSON;
			my $hash = $j->decode( join( "\n", $fh->getlines() ) );
			$self->initialize_logging( %{$hash} );
			$fh->close();
		} else {
			die $self->graceful_error("failed to configure logging.");
		}
	}

	$self->{_cgi} = new CGI;
	$self;
}

sub _db_session_encrypt_argument($$) {
	my $self     = shift;
	my $encodeme = shift;

	my $dbh = $self->dbh;

	#
	# get a per-session key for encrypting arguments to the db
	#
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

sub get_device_authorization {
	my $self   = shift @_;
	my $app    = shift @_;
	my $device = shift @_;

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached( qq{
		SELECT *
		FROM	service_device_permitted_authentication
		WHERE	service_endpoint_uri = ?
		AND	device_name = ?
		LIMIT 1
	} ) || die $self->graceful_error("temporary issue setting up device lookup");

	$sth->execute( $app, $device )
	  || die $self->graceful_error("temporary issue getting device info");

	my $hr = $sth->fetchrow_hashref;

	$sth->finish;
	$hr;
}

sub get_jwt_signing_key {
	my $self = shift @_;
	my $app  = shift @_;

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached( qq{
		SELECT *
		FROM	service_jwt_signing_keys
		WHERE	service_endpoint_uri = ?
		LIMIT 1
	} ) || die $self->graceful_error("temporary issue looking up signing key");

	$sth->execute($app)
	  || die $self->graceful_error("temporary issue fetching signing key");

	my $hr = $sth->fetchrow_hashref;
	$sth->finish;

	return undef if ( !$hr );

	#
	# This means vault
	#
	if ( $hr->{external_id} ) {
		my $r = JazzHands::AppAuthAL::find_and_parse_auth('jazzhands-oauth-jwt-minter')
		  || die $self->graceful_error(
			"Temporary Issues retrieving signing key");

		if ( !$r->{private_key} ) {
			die $self->graceful_error(
				"Configuration error with how to find private keys from vault");
		}

		# this is somewhat gross because it does not actually login and is
		# just stealing the caching logic
		my $args = {};
		my @errors;

		my $cached_args = {
			options => $r->{options},
			errors  => \@errors,
		};

		$r->{private_key}->{VaultPath} = $hr->{external_id};
		do_cached_login( $cached_args, $r->{private_key},
			sub { $args = $_[1]; 1; }, \$args );

		if ( !$args ) {
			$self->log(
				'fatal',
				"Temporary issue errors: ",
				Dumper( \@errors )
			);
			die $self->graceful_error(
				"Temporary issue retrieving secure signing key");
		}

		$hr->{private_key} = $args->{private_key};

	}
	$hr->{private_key};
}

sub authenticate_account($$$) {
	my $self        = shift @_;
	my $accounthash = shift @_;
	my $password    = shift @_;

	my $account_id  = $accounthash->{account_id};
	my $encryptedpw = $self->_db_session_encrypt_argument($password);

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

	$sth->bind_param( ':acid',   $account_id )        || die $sth->errstr;
	$sth->bind_param( ':pwd',    $encryptedpw )       || die $sth->errstr;
	$sth->bind_param( ':method', 'aes-cbc/pad:pkcs' ) || die $sth->errstr;

	if ( !( $sth->execute() ) ) {
		my $state = $dbh->state;
		my $msg   = $dbh->errstr;

		$self->log( 'fatal', "Temporary issues authenticating user: %s", $msg );
		die $self->graceful_error("temporary issue authenticating user");
	}

	my ($boolean) = $sth->fetchrow_array;
	$sth->finish;
	($boolean) ? 1 : 0;

}

sub process_authentication_method($$$) {
	my $self     = shift @_;
	my $username = shift @_;
	my $method   = shift @_;
	my $scope    = shift @_;

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached(
		qq{
		SELECT translated_login AS login, max_token_lifetime
		FROM	authentication_rules
		WHERE	login = ?
		AND		permitted_authentication_method = ?
		AND		service_endpoint_uri = ?
		ORDER BY permitted_authentication_method, translated_login, login
		LIMIT 1
	}
	  )
	  || die $self->graceful_error(
		"temporary database issue setting up check for authorization method");

	$sth->execute( $username, $method, $scope )
	  || die $self->graceful_error(
		"temporary database issue checking authorization method");

	my $hr = $sth->fetchrow_hashref;
	$sth->finish;
	$hr;
}

sub can_impersonate_device($$$) {
	my $self     = shift @_;
	my $service  = shift @_;
	my $login    = shift @_;
	my $behalfof = shift @_;

	$behalfof =~ s,^(device|host)/,,;

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached( qq{
		SELECT count(*)
		FROM	permitted_device_impersonation
		WHERE	service_endpoint_uri = ?
		AND		login = ?
		AND		actas = ?
	} )
	  || die $self->graceful_error(
		"temporary database issue setting up check for authorization method");

	$sth->execute( $service, $login, $behalfof )
	  || die $self->graceful_error(
		"temporary ddatabase issue checking authorization method");

	my ($tally) = $sth->fetchrow_array;
	$sth->finish;
	$tally;
}

sub can_impersonate_account($$$) {
	my $self     = shift @_;
	my $service  = shift @_;
	my $login    = shift @_;
	my $behalfof = shift @_;

	my $dbh = $self->dbh;
	my $sth = $dbh->prepare_cached( qq{
		SELECT 	translated_actas
		FROM	permitted_account_impersonation
		WHERE	service_endpoint_uri = ?
		AND		login = ?
		AND		actas = ?
		ORDER BY service_endpoint_uri, login, translated_actas, actas
		LIMIT 1
	} )
	  || die $self->graceful_error(
		"temporary database issue setting up check for authorization method");

	$sth->execute( $service, $login, $behalfof )
	  || die $self->graceful_error(
		"temporary database issue checking authorization method");

	my ($xlate) = $sth->fetchrow_array;
	$sth->finish;
	$xlate;
}

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
	) || die $self->graceful_error("error setting up query");

	$sth->execute($login) || die $self->graceful_error("running account query");
	my $hr = $sth->fetchrow_hashref;
	$sth->finish;
	$hr;
}

sub cgi($) {
	my $self = shift @_;
	$self->{_cgi};
}

sub dbh($) {
	my $self = shift @_;
	if ( !exists( $self->{_dbh} ) ) {
		my $dbh =
		  JazzHands::DBI->connect( 'jazzhands-oauth-jwt-minter',
			{ AutoCommit => 0, PrintError => 1 } );
		if ( !$dbh ) {
			$self->log( 'fatal', 'database error: $%s',
				$JazzHands::DBI::errstr );
			die $self->graceful_error( {
				error             => 'temporarily_unavailable',
				error_description => "database issues"
			} );
		}
		$self->{_dbh} = $dbh;
	}
	$self->{_dbh};
}

sub graceful_error($$) {
	my $self = shift @_;
	my $body = shift @_;

	my $rv;
	if ( ref($body) eq 'HASH' ) {
		$rv = $body;
	} else {
		$rv = {
			error             => 'temporarily_unavailable',
			error_description => $body
		};
	}

	print $self->{_cgi}->header(
		-type   => 'application/json',
		-status => '400 Bad Request',
	);

	my $j = new JSON;
	my $p = $j->encode($rv);
	print $p, "\n";
	exit(0);
}

sub authentication_dance($) {
	my $self = shift @_;

	my $cgi    = $self->cgi;
	my $params = {};

	#
	# XXX - really need to sort this out by input scopes or something?
	# I _could_ look at the host that the request came into although that
	# only works if the minter lives at the same place as the api.
	# for now, I'm just hardcoding it, and this may just turn into a config
	# file option or some such that gets figured out.  Yuck.

	#
	# The details of the various grant-types are described in rfc7591 (sec 4).
	# This implementation is a bit more restrictive about extra parameters
	# than the rfc specifies.   Except in the case of acting as another user,
	# which is an added parameter
	#
	if ( $ENV{'CONTENT_TYPE'} eq 'application/json' ) {
		my $j = new JSON;
		$params = $j->decode( scalar $cgi->param('POSTDATA') );
	} elsif ( $ENV{'CONTENT_TYPE'} eq 'application/x-www-form-urlencoded' ) {
		for my $t (qw(grant_type nonce scope username password on_behalf_of)) {
			if ( my $v = $cgi->param($t) ) {
				$params->{$t} = $v;
			}
		}
	} else {
		die $self->graceful_error( {
			error             => 'invalid_request',
			error_description => "malformed request"
		} );
	}

	my $gt = $params->{'grant_type'};

	if ( !$gt ) {
		die $self->graceful_error( {
			error             => 'invalid_request',
			error_description => "malformed request"
		} );

	}

	my $role;
	my $subject;
	my $authduser;
	my $method;
	my $onbehalfof;
	my $device;

	my $maxlifetime;

	my $jwt = {};

	#
	# This really needs to be properly implemented and checked, but for now...
	#
	if ( my $nonce = $params->{'nonce'} ) {
		$jwt->{nonce} = $nonce;
	} else {
		die $self->graceful_error( {
			error             => 'invalid_request',
			error_description => "must specify a nonce"
		} );
	}

	# if there is no scope specified, then error out.  The user must say what
	# they expect the token to be used for.  This endpoint only issues JWTs for
	# one and only one scope.  Validity of scope is not checked.  Invalid
	# scopes will just error out as though things aren't permitted.
	my $scope = $params->{'scope'};
	if ( !$scope ) {
		die $self->graceful_error( {
			error             => 'invalid_request',
			error_description => "must specify requested scope"
		} );
	}

	#
	# client_credentials means that the user is to be authenticated by apache
	# in some way.   This is incompatible with setting a password, so it just
	# rejects it outright so bad implementations do not leave passwords sitting
	# around.
	#
	# In this case, the only alternative is negotiate, so no attempt is made
	# to look up the user, they're just sent back things to trigger a
	# "negotiate" negotation.
	#
	# There is no concept of a username/password for devices although that may
	# make sense to revisit.  The expected way for devices to authenticate is
	# either via a kerberos ticket or client TLS.  Client TLS, however, is not
	# supported but likely could easily be.
	#
	if ( $gt eq 'client_credentials' ) {
		if ( !$cgi->remote_user() ) {
			if ( $params->{'password'} ) {
				die $self->graceful_error( {
					error             => 'invalid_request',
					error_description =>
					  "passwords not permitted for grant type $gt"
				} );
			}
			print $cgi->header(
				-charset          => 'UTF-8',
				-status           => '401 Unauthorized',
				-type             => 'text/html',
				-WWW_Authenticate => 'Negotiate',
			);
			print "\n\n";
			print $cgi->start_html, "Use Kerberos";
			print $cgi->end_html;
			exit(0);
		}

		# We have a username, which we assume comes from a negotiate
		# session.  If support for something in addition to negotiate is
		# required, some cleveness will need to be figured out here.

		# negotate headers that start with host/whatever are acutally for
		# hosts and need to be handled in a special way for postgrest
		my $username = $cgi->remote_user;
		$username =~ s/\@.*$//;

		if ( $username =~ m,host/(.+)$, ) {
			$subject = $1;

			#
			# device is scoped outside all this down so that it can be
			# processed later by "on behalf of" if set.
			#
			$device = $self->get_device_authorization( $scope, $subject );

			# XXX should be dynamic
			$authduser = $username;
			#
			# check to see if the device is allowed to authenticate
			#
			if ( !$device ) {
				die $self->graceful_error( {
					error             => 'access_denied',
					error_description =>
					  "Invalid or device not permitted for this service"
				} );
			}

			$role        = $device->{device_role};
			$maxlifetime = $device->{max_token_lifetime};
		} elsif (
			my $hr = $self->process_authentication_method(
				$username, 'negotiate', $scope
			)
		  )
		{
			if ($hr) {
				$role    = $hr->{login};
				$subject = $authduser = $username;
			} else {

				# this never is actually achived because the outter if
				# results in $hr never getting set.
				die $self->graceful_error( {
					error             => 'access_denied',
					error_description =>
					  "method negotiate is not permitted for this account"
				} );
			}
			$maxlifetime = $hr->{max_token_lifetime};
		} else {
			my $j = new JSON;
			$self->log( 'fatal', 'Not permitted: negotiate %s',
				$j->encode($params) );
			die $self->graceful_error( {
				error             => 'access_denied',
				error_description =>
				  "negotiate method is not permitted for this account"
			} );
		}
	} elsif ( $gt eq 'password' ) {
		my $username = $params->{'username'};
		my $password = $params->{'password'};
		if ( !$username || !$password ) {
			die $self->graceful_error( {
				error             => 'invalid_request',
				error_description => "malformed request"
			} );
		}

		if ( !(
			my $hr = $self->process_authentication_method(
				$username, 'password', $scope
			)
		) )
		{
			if ( $hr->{login} ) {
				$role    = $hr->{login};
				$subject = $authduser = $username;
			} else {
				my $j = new JSON;
				$self->log( 'fatal', 'Not permitted: password %s',
					$j->encode($params) );
				die $self->graceful_error( {
					error             => 'access_denied',
					error_description =>
					  "method password is not permitted for this account"
				} );
			}
			$maxlifetime = $hr->{max_token_lifetime};
		}

		my $u = $self->get_account($username);
		if ( !$u ) {
			die $self->graceful_error( {
				error             => 'access_denied',
				error_description => "user is not authorized or does not exist"
			} );
		}

		if ( !$self->authenticate_account( $u, $password ) ) {
			die $self->graceful_error( {
				error             => 'access_denied',
				error_description => "invalid password or user does not exist"
			} );
		}
		$method    = 'password';
		$authduser = $username;
	} else {
		$self->graceful_error( {
			error             => 'unsupported_grant_type',
			error_description => "invalid grant type $gt"
		} );
	}

	# At this point, $authduser is set to the login of an authenticated user
	# who was permitted to get this far.

	# legacy jwt - this is not relevant.
	# my $jwt = {
	#          'tvn' => 1,
	#          'exp' => 2383578847,
	#          'role' => 'kovert',
	#          'ist' => '2021-07-19 17:14:07.517856',  <- wrong
	#          'iss' => 'your mom',
	#          'aud' => 'nginxfqdn'
	#};

	$role    = $authduser if ( !$role );
	$subject = $role      if ( !$subject );

	if ( my $fakeit = $params->{'on_behalf_of'} ) {
		if ( $fakeit =~ s,^(host|device)/,, ) {
			if ( $self->can_impersonate_device( $scope, $authduser, $fakeit ) )
			{
				#
				# if we got this far, the user is allowed to authenticate as
				# this user, but now see if the device is allowed to use this
				# endpoint.
				#
				# $device is consumed later (it could also be set if the
				# device itself authenticated.
				#
				$device = $self->get_device_authorization( $scope, $fakeit );
				$role   = $device->{device_role};
				if ( !$device ) {
					die $self->graceful_error( {
						error             => 'access_denied',
						error_description =>
						  "Invalid or device not permitted for this service"
					} );
				}
				$onbehalfof = $subject = $fakeit;
			} else {
				die $self->graceful_error( {
					error             => 'access_denied',
					error_description =>
					  "may not issue tokens on behalf of that device or device does not exist"
				} );
			}
		} else {
			if ( (
				my $xlate =
				$self->can_impersonate_account( $scope, $authduser, $fakeit )
			) )
			{
				$onbehalfof = $subject = $fakeit;
				$role       = $xlate;
			} else {
				die $self->graceful_error( {
					error             => 'access_denied',
					error_description =>
					  "may not issue tokens on behalf of that user"
				} );
			}
		}
	}

	if ($device) {

		# fill in interesting things
		$jwt->{device_id} = $device->{device_id};
	}

	$jwt->{scope} = $scope;
	$jwt->{sub}   = $subject;    # who this is for, which often matches role
	$jwt->{role}  = $role;       # postgrest specific thing for dbrole

	$jwt->{token_lifetime} = $maxlifetime if ($maxlifetime);

	if ($onbehalfof) {
		$jwt->{act} = { 'sub' => $authduser };
	}

	$jwt;
}

sub mint_jwt($) {
	my $self = shift @_;

	my $jwtbase = $self->authentication_dance();
	my $scope   = $jwtbase->{scope};               # XXX - dup'd elsewhere

	my $lifetime = $jwtbase->{token_lifetime} || 3600;
	delete( $jwtbase->{token_lifetime} );

	# postgrest calls this audience.
	# This should _probably_ be dynamic.
	delete( $jwtbase->{scope} );

	# should pull from the db
	my $now = time;

	# something to tie back to this process for log rifling.
	my $issuer = hostname . "_oauthminter";
	my $uuid   = uuid();

	$jwtbase->{aud} = $scope;            # audiences for which this JWT is valid
	$jwtbase->{iss} = $issuer;           # Issuer
	$jwtbase->{exp} = $now + $lifetime;  # Expiration
	$jwtbase->{nbf} = $now;              # for completeness
	$jwtbase->{ist} = $now;              # when it was issued
	$jwtbase->{jti} = $uuid;             # unique id, which should be logged XXX

	# XXX - setup list of things that are authorized with this private
	# key and this access method for this user and any other restrictions
	# we may want to add - refine scope

	my $key = $self->get_jwt_signing_key($scope);
	if ( !$key ) {
		$self->log(
			"There appears to be no JWT signing key in the database for scope %s",
			$scope
		);
		die $self->graceful_error("Issue getting the JWT signing key");
	}

	my $j      = new JSON;
	my $bearer = encode_jwt(
		payload => $j->encode($jwtbase),
		alg     => 'RS256',
		key     => Crypt::PK::RSA->new( \$key )
	);

	my $behalf  = "";
	my $rolestr = "";
	if ( ( exists( $jwtbase->{act} ) ) && ( exists( $jwtbase->{act}->{sub} ) ) )
	{
		$behalf = sprintf " (behalf of %s)", $jwtbase->{act}->{sub};
	}
	if ( exists( $jwtbase->{role} ) ) {
		$rolestr = sprintf " for role %s", $jwtbase->{role};
	}
	$self->log( 'info', "Issued: %s to %s%s%s scope %s until %s",
		$jwtbase->{jti}, $jwtbase->{sub}, $behalf, $rolestr, $jwtbase->{aud},
		$jwtbase->{exp} );

	my $rv = {
		token_type   => 'Bearer',
		access_token => $bearer,
		scope        => $scope,
		expires_in   => $lifetime,
	};

	# Not bothering with this, though probably could
	my $idtoken;
	if ($idtoken) {
		$rv->{id_token} = $idtoken;
	}

	my $p = $j->encode($rv);

	print $self->{_cgi}->header( -type => 'application/json', );
	print $p, "\n";
	return (0);
}

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
use utf8;

# optional file
if ( defined( my $logfn = "/etc/jazzhands/minter_logging.cfg" ) ) {
	my $log;
	if ( -r $logfn ) {
		$log->{'log_config_filename'} = $logfn;

	}
	my $x = new worker( %{$log} );
	$x->mint_jwt();
}

exit 0;
