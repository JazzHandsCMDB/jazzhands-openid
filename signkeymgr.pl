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

=head1 signkeymgr

signkeymgr - basic signing key management for oauth servers

=head1 SYNOPSIS

signkeymgr --authapp name | --dbhost fqdn [ --database db ] --vaultserver server ]  subcommand

signkeymgr save [ --keypath /path/to/key | --generate | --existing-service servicename ] --vaultpath path/in/vault --service servicename
signkeymgr list 
signkeymgr export [ --jwk | --privatekey | --key-id ]
	--service service

=head1 DESCRIPTION

signkeymgr is used to list and manage the X509 private keys used to
sign JWTs for use by postgrest and other bearer token based applciations.

An --appauth can be specified which will cause it to use the
JazzHands::AppAuthAL module to figure out how to talk to the database,
otherwise fall back to Kerberos is assumed.  If kerberos is assumed the
--dbhost and --database arguments are used to determine to where to establish a connection.

The vaultserver can also be defined in the appauthal or on the command line.

The list command shows all the applications with keys and where theh are in
vault.

The save command is used to put a key in the databse for a given application.
It is possible to have this script geenrate a key and insert that.  The path
in vault is where it should be saved with a key of private_key.

The export command will list the public jwk for the private key, the private
key itself, or the databse key-id, depending on which argument.

=head1 ENVIRONMENT

The VAULT_ADDR, VAULT_TOKEN and VAULT_CA_PATH envirnoment variables are
honored over anything on the commandline, and if specified, the environment
wins (This is all a feature of JazzHands::Vault).

=head1 BUGS

It should be possible to fallback to a username and password

Only RSA keys are supported.

Should allow depositing the keys in the database directly...

=head1 AUTHOR

Todd Kover, kovert@omniscient.com

=cut

package Worker;

use strict;
use warnings;
use JazzHands::Vault;
use JazzHands::DBI;
use DBI;
use JSON;
use FileHandle;
use File::Temp qw(tempfile);
use Digest::SHA qw(sha1_hex sha256_hex);

our $errstr;

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;

	my $self = bless {}, $class;

	my %args = @_;

	$self->{_authapp} = $args{authapp};

	#
	# see if we can login to the db with appauth information first
	#
	if ( $args{dbhost} && $args{database} ) {
		my $dsn = sprintf "DBI:Pg:database=%s;host=%s",
		  $args{database}, $args{dbhost};
		if ( my $dbh = DBI->connect( $dsn, undef, undef, { AutoCommit => 0 } ) )
		{
			$self->{_dbh} = $dbh;
		} else {
			$errstr = DBI::errstr;
			return undef;
		}
	}

	if ( $self->{_appauth} ) {
		my $dbh =
		  JazzHands::DBI->connect( $self->{_appauth}, { AutoCommit => 0 } );
		if ( !$dbh ) {

			# this is gross
			my $e = JazzHands::DBI::errstr;
			if ( $e !~ /Application not given|auth entry/ ) {
				$errstr =
				  "DB Initialization issue: " . JazzHands::DBI::errstr return
				  undef;
			}
		}
		$self->{_dbh} = $dbh;

		my $appauth =
		  JazzHands::AppAuthAL::find_and_parse_auth( $self->{_appauthal},
			undef, 'vault' );
		if ($appauth) {
			$self->{_vault} = new JazzHands::Vault( %{$appauth} );

		}
	}

	if ( $args{vaultserver} ) {
		$self->{_vaultserver} = $args{vaultserver};
		if ( !$self->{_vaultserver} ) {
			$errstr = "Must set vault server";
			return undef;
		}

		if ( !$self->{_vault} && $ENV{'VAULT_TOKEN'} ) {

			my ( $fh, $fn ) = tempfile();
			$fh->print( $ENV{'VAULT_TOKEN'}, "\n" );
			$fh->close;
			my $v = new JazzHands::Vault(
				VaultServer    => $self->{_vaultserver},
				VaultTokenPath => $fn
			);
			unlink($fn);
			if ( !$v ) {
				$errstr =
				  sprintf( "Environment Variable VAULT_TOKEN in invalid (%s)",
					JazzHands::Vault::errstr );
				return undef;
			}
			$self->{_vault} = $v;
		}

		if ( !$self->{_vault} ) {
			my $v = new JazzHands::Vault(
				VaultServer    => $self->{_vaultserver},
				VaultTokenPath => $ENV{'HOME'} . "/.vault-token"
			);
			if ( !$v ) {
				$errstr = sprintf
				  "Must sign into vault and deposit a token in ~/.vault_token or set VAULT_TOKEN (%s)",
				  JazzHands::Vault::errstr;
				return undef;
			}
			$self->{_vault} = $v;
		}
	}

	$self;
}

sub errstr {
	return $errstr;
}

sub vault_write($$$) {
	my $self      = shift @_;
	my $vaultpath = shift @_;
	my $hash      = shift @_;

	my $v = $self->{_vault};

	if ( my $r = $v->write( $vaultpath, { data => $hash } ) ) {
		return $r;
	} else {
		$errstr = $v->errstr;
	}
	undef;

}

sub vault_read($$) {
	my $self      = shift @_;
	my $vaultpath = shift @_;

	my $v = $self->{_vault};

	if ( my $r = $v->read($vaultpath) ) {
		return $r;
	} else {
		$errstr = $v->errstr;
	}
	undef;
}

sub find_key($$) {
	my $self = shift @_;
	my $pk   = shift @_;

	my $sth = $self->{_dbh}->prepare_cached( qq{
		SELECT	private_key_id, external_id
		FROM	private_key
				JOIN public_key_hash USING (public_key_hash_id)
				JOIN public_key_hash_hash USING (public_key_hash_id)
		WHERE	x509_fingerprint_hash_algorighm = ?
		AND		calculated_hash = ?
	} );

	if ( !$sth ) {
		$errstr = $self->{_dbh}->errstr;
		return undef;
	}

	my $d256 = sha256_hex( $pk->export_key_der('public') );
	if ( !$sth->execute( 'sha256', $d256 ) ) {
		$errstr = $sth->errstr;
		$sth->finish;
		return undef;
	}

	if ( my $hr = $sth->fetchrow_hashref() ) {
		$sth->finish;
		return $hr;
	}

	my $d1 = sha1_hex( $pk->export_key_der('public') );
	if ( !$sth->execute( 'sha1', $d256 ) ) {
		$errstr = $sth->errstr;
		$sth->finish;
		return undef;
	}
	if ( my $hr = $sth->fetchrow_hashref() ) {
		$sth->finish;
		return $hr;
	}

	undef;
}

sub get_existing_service_key($$) {
	my $self    = shift @_;
	my $service = shift @_;

	my $sth = $self->{_dbh}->prepare_cached( qq{
		SELECT	pk.external_id, pk.private_key_id
		FROM	private_key pk
				JOIN property p
					ON pk.private_key_id = p.property_value_private_key_id
				JOIN service_version_collection
					USING (service_version_collection_id)
		WHERE	service_version_collection_type = 'current-services'
		AND		service_version_collection_name = ?
	} ) || die $self->{_dbh}->errstr;

	$sth->execute($service) || die $sth->errstr;

	my $rv = $sth->fetchrow_hashref;
	$sth->finish;
	$rv;
}

sub add_key($$) {
	my $self      = shift @_;
	my $pk        = shift @_;
	my $vaultpath = shift @_;

	my $d1   = sha1_hex( $pk->export_key_der('public') );
	my $d256 = sha256_hex( $pk->export_key_der('public') );

	if ( !$d1 || !$d256 ) {
		$errstr = "Could not generate sha1 and sha256 hash";
		return undef;
	}

	my $sth = $self->{_dbh}->prepare_cached( qq{
		WITH ph AS (
			INSERT INTO public_key_hash (description) VALUES (NULL) RETURNING *
		), hashes AS (
			INSERT INTO public_key_hash_hash (
				public_key_hash_id, x509_fingerprint_hash_algorighm, calculated_hash
			)
			SELECT  public_key_hash_id, 'sha1', :sha1 FROM ph
				UNION
			SELECT  public_key_hash_id, 'sha256', :sha256 FROM ph
			RETURNING *
		) INSERT INTO private_key (
				private_key_encryption_type, public_key_hash_id,
				external_id
			) SELECT :type, public_key_hash_id,
				:vaultpath
			FROM ph
			RETURNING external_id, private_key_id
	} );

	if ( !$sth ) {
		$errstr = $self->{_dbh}->errstr;
		return undef;
	}

	$sth->bind_param( ':sha1',      $d1 )        || die $sth->errstr;
	$sth->bind_param( ':sha256',    $d256 )      || die $sth->errstr;
	$sth->bind_param( ':type',      'rsa' )      || die $sth->errstr;
	$sth->bind_param( ':vaultpath', $vaultpath ) || die $sth->errstr;

	if ( !$sth->execute() ) {
		$errstr = $sth->errstr;
		return undef;
	}

	my $hr = $sth->fetchrow_hashref;
	$sth->finish;
	$hr;
}

sub add_signing_key_to_service($$$) {
	my $self    = shift @_;
	my $service = shift @_;
	my $pkid    = shift @_;

	if ( !$service || !$pkid ) {
		$errstr = "Must specify service and keyinfo";
		return undef;
	}

	my $sth = $self->{_dbh}->prepare_cached( qq{
		INSERT INTO property (
			property_type, property_name,
			service_version_collection_id, property_value_private_key_id
		) SELECT 'jazzhands-openid', 'jwt-signer',
			service_version_collection_id, :pkid
		FROM service_version_collection
		WHERE service_version_collection_name = :service
		AND service_version_collection_type = 'current-services'
		RETURNING *
	} );

	if ( !$sth ) {
		$errstr = "prepare: " . $self->{_dbh}->errstr;
		return undef;
	}

	$sth->bind_param( ':service', $service ) || die $sth->errstr;
	$sth->bind_param( ':pkid',    $pkid )    || die $sth->errstr;

	if ( !$sth->execute() ) {
		$errstr = "exectue: " . $sth->errstr;
		return undef;
	}
	my $hr = $sth->fetchrow_hashref;
	$sth->finish;
	if ( !$hr ) {
		$errstr = "No rows inserted";
		return undef;
	}
	1;
}

sub get_apps($) {
	my $self = shift @_;

	my $sth = $self->{_dbh}->prepare_cached( qq{
		SELECT	property_id, pk.private_key_id, pk.private_key, 
				pk.external_id AS vault_path,
				s.service_type, s.service_name
		FROM property p
			JOIN service_version_collection USING
				(service_version_collection_id)
			JOIN service_version_collection_service_version USING
				(service_version_collection_id)
			JOIN service_version USING (service_version_id)
			JOIN service s USING (service_id)
			JOIN private_key pk
				ON pk.private_key_id = p.property_value_private_key_id
		WHERE property_type = 'jazzhands-openid'
		AND property_name = 'jwt-signer'
		ORDER BY s.service_type, s.service_name, property_id
	} );

	if ( !$sth ) {
		$errstr = "prepare: " . $self->{_dbh}->errstr;
		return undef;
	}

	if ( !$sth->execute() ) {
		$errstr = "exectue: " . $sth->errstr;
		return undef;
	}

	my $hrs = $sth->fetchall_hashref('property_id');
	$sth->finish;
	$hrs;
}

sub commit {
	my $self = shift @_;

	$self->{_dbh}->commit();
}

DESTROY {
	my $self = shift @_;

	if ( my $dbh = $self->{_dbh} ) {
		$dbh->rollback;
		$dbh->disconnect;
	}
}
1;

#==============================================================================

package main;
use Getopt::Long qw(:config pass_through);
use Pod::Usage;
use Crypt::PK::RSA;

#==============================================================================

# things that do the work.  Arguably should be subroutines of Worker which
# which would be possible

sub savekey($) {
	my $work = shift @_;

	my $keypath;
	my $vaultpath;
	my $service;
	my $generate;
	my $eservice;

	GetOptions(
		'vaultpath=s'        => \$vaultpath,
		'keypath=s'          => \$keypath,
		'service=s'          => \$service,
		'generate'           => \$generate,
		'existing-service=s' => \$eservice,
	) || die pod2usage(1);

	if ( !$service ) {
		die "Must specify existing service to attach to";
	}

	if ( $eservice && ( $keypath || $generate ) || ( $keypath && $generate ) ) {
		die
		  "Must specify one of an existing service, keypath or to generate a new key";
	}

	my $keyinfo;
	if ($eservice) {
		$keyinfo = $work->get_existing_service_key($eservice);
		if ( !$keyinfo ) {
			die sprintf "Could not find private key for existing service: %s\n",
			  $eservice;
		}
	} else {
		my $pk = new Crypt::PK::RSA;
		if ($keypath) {
			$pk->import_key($keypath);
		} elsif ($generate) {
			$pk->generate_key(512);
		} else {
			die
			  "Must specify either the path to a key, indicate generation, or an existing service";
		}

		if ( !( $keyinfo = $work->find_key($pk) ) ) {
			if ( !$vaultpath ) {
				die "Must specify vault path to store the new private key";
			}
			$work->vault_write( $vaultpath,
				{ 'private_key' => $pk->export_key_pem('private') } )
			  || die $work->errstr;
			$keyinfo = $work->add_key( $pk, $vaultpath );
		}
	}

	if ($service) {
		$work->add_signing_key_to_service( $service,
			$keyinfo->{private_key_id} )
		  || die $work->errstr;
	}

}

sub listkeys($) {
	my $work = shift @_;

	my $map = $work->get_apps();

	my $fmt = "%*s %s %s\n";

	my $maxsvc = 0;
	foreach my $propid ( keys %{$map} ) {
		my $mix = join( ":",
			$map->{$propid}->{service_type},
			$map->{$propid}->{service_name} );
		$maxsvc = length($mix) if length($mix) > $maxsvc;
	}

	printf( $fmt, $maxsvc, "Service", "PKID", "Vault Location" );
	printf(
		"==================================================================\n");

	foreach my $propid ( sort keys %{$map} ) {
		my $mix = join( ":",
			$map->{$propid}->{service_type},
			$map->{$propid}->{service_name} );
		printf( $fmt,
			$maxsvc, $mix,
			$map->{$propid}->{private_key_id},
			$map->{$propid}->{vault_path} || '' );
	}

}

sub exportkeyinfo($) {
	my $work = shift @_;

	my ($jwk);
	my ($privatekey);
	my ($service);
	my ($keyid);

	GetOptions(
		'jwk'        => \$jwk,
		'privatekey' => \$privatekey,
		'service=s'  => \$service,
		'key-id=s'   => \$keyid,
	) || die pod2usage(1);

	if ( !$service ) {
		die "Must specify service\n";
	}

	# specify only one
	if ( !$service ) {
		die "Must specify service\n";
	}

	# specify only one
	if ( $jwk && $privatekey ) {
		die "Must specify one of privatekey or jwk\n";
	}

	my $pem;
	my $keyinfo;
	if ( $keyinfo = $work->get_existing_service_key($service) ) {
		if ( my $r = $work->vault_read( $keyinfo->{external_id} ) ) {
			$pem = $r->{private_key};
			if ( !$pem ) {
				die "private key not stored properly.\n";
			}
		} else {
			die sprintf "Unable to retrieve key: %s", $!;
		}
	} else {
		die sprintf "Could not find key for service %s\n", $service;
	}

	if ($privatekey) {
		print $pem;
	} elsif ($keyid) {
		print $keyinfo->{private_key_id}, "\n";
	} elsif ($jwk) {
		my $pk = new Crypt::PK::RSA->new( \$pem ) || die $!;
		print $pk->export_key_jwk('public');
	} else {
		die "No action specified.";
	}

}

#==============================================================================

my $vaultserver;
my $vaultpath;
my $authapp;
my $dbhost;
my $database;

my $commands = {
	'save' => {
		func    => \&savekey,
		require => [qw(dbh vault)],
	},
	'list' => {
		func    => \&listkeys,
		require => [qw(dbh)],
	},
	'export' => {
		func    => \&exportkeyinfo,
		require => [qw(dbh vault)],
	}

};

GetOptions(
	'vaultserver=s' => \$vaultserver,
	'authapp=s'     => \$authapp,
	'dbhost=s'      => \$dbhost,
	'database=s'    => \$database,
);

my $subcommand = shift @ARGV || die pod2usage(2);

die sprintf "Unknown subcommand %s", $subcommand
  if ( !$commands->{$subcommand} );

my $work = new Worker(
	dbhost      => $dbhost,
	database    => $database,
	vaultserver => $vaultserver,
	authapp     => $authapp,
) || die $Worker::errstr;

if ( scalar(
	grep( $_ eq 'dbh', @{ $commands->{$subcommand}->{require} } )
	  && !( $work->{_dbh} )
) )
{
	die "Must provide enough information for a database connection";
}

if ( scalar(
	grep( $_ eq 'vault', @{ $commands->{$subcommand}->{require} } )
	  && !( $work->{_vault} )
) )
{
	die "Must provide enough information for a vault connection";
}

$commands->{$subcommand}->{func}->($work);

$work->{_dbh}->commit;
