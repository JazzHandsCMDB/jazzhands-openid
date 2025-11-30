#!/usr/local/bin/perl

use strict;
use warnings;

package LogoffCode;

use strict;
use warnings;
use CGI;
use CGI::Carp qw(fatalsToBrowser);
use HTML::Tiny;
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

	$self->{cgi} = $cgi;
	$self->{h}   = $h;

	return bless $self, $class;
}

# Method to generate the logoff page
sub generate_logoff_page {
	my ( $self, $has_gssapi_cookie ) = @_;

	my $cgi = $self->{cgi};
	my $h   = $self->{h};

	my $body_content = [
		$h->h1(['Session Management']),
		$h->p(['Choose an action below:']),
		$h->br,
	];

	# Show Clear GSSAPI button only if the cookie is set
	if ($has_gssapi_cookie) {
		push @$body_content,
		  $h->form(
			{ method => 'POST', action => $cgi->url(-absolute => 1) },
			[
				$h->input(
					{
						type  => 'hidden',
						name  => 'action',
						value => 'clear_gssapi'
					}
				),
				$h->button(
					{
						type    => 'submit',
						onclick => 'this.form.submit(); return false;'
					},
					['Clear GSSAPI Preference']
				),
				$h->p(
					{ style => 'margin-left: 20px; color: #666;' },
					['Remove saved GSSAPI authentication preference']
				),
			]
		  );
		push @$body_content, $h->br;
	}

	# Always show Log Off button
	push @$body_content,
	  $h->form(
		{ method => 'POST', action => $cgi->url(-absolute => 1) },
		[
			$h->input(
				{
					type  => 'hidden',
					name  => 'action',
					value => 'logoff'
				}
			),
			$h->button(
				{
					type    => 'submit',
					onclick => 'this.form.submit(); return false;'
				},
				['Log Off']
			),
			$h->p(
				{ style => 'margin-left: 20px; color: #666;' },
				['Clear your session and log out']
			),
		]
	  );

	my $html = $cgi->start_html(
		-title => 'Session Management',
		-style => {
			-code => '
				body { font-family: Arial, sans-serif; margin: 40px; }
				h1 { color: #333; }
				form { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background: #f9f9f9; }
				button { padding: 10px 20px; font-size: 14px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
				button:hover { background-color: #0056b3; }
				p { margin: 5px 0; }
			'
		}
	);

	$html .= join( '', @$body_content );
	$html .= $cgi->end_html;

	return $html;
}

# Method to generate the confirmation page after action
sub generate_confirmation_page {
	my ( $self, $action ) = @_;

	my $cgi = $self->{cgi};
	my $h   = $self->{h};

	my $message;
	if ( $action eq 'clear_gssapi' ) {
		$message = 'GSSAPI preference has been cleared.';
	} elsif ( $action eq 'logoff' ) {
		$message = 'You have been logged off. Your session has been cleared.';
	} else {
		$message = 'Action completed.';
	}

	my $body_content = [
		$h->h1(['Action Complete']),
		$h->p( [ $h->strong([$message]) ] ),
		$h->br,
		$h->p(
			[
				$h->a( { href => $cgi->url(-absolute => 1) },
					['Return to Session Management'] )
			]
		),
	];

	my $html = $cgi->start_html(
		-title => 'Action Complete',
		-style => {
			-code => '
				body { font-family: Arial, sans-serif; margin: 40px; }
				h1 { color: #333; }
				a { color: #007bff; text-decoration: none; }
				a:hover { text-decoration: underline; }
			'
		}
	);

	$html .= join( '', @$body_content );
	$html .= $cgi->end_html;

	return $html;
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

# Create LogoffCode object
my $logoff = LogoffCode->new(
	cgi => $cgi,
	h   => $h,
);

unless ($logoff) {
	print $cgi->header( -type => 'text/html', -charset => 'utf-8' );
	print $cgi->start_html('Error');
	print $h->p( ['Failed to initialize: ' . $LogoffCode::errstr] );
	print $cgi->end_html;
	exit;
}

# Get current cookies
my $gssapi_cookie = $cgi->cookie('oauth_favor_gssapi');
my $session_cookie = $cgi->cookie('oauth_session');

# Get action parameter
my $action = $cgi->param('action') || '';

# Variables to hold output and optional cookie
my $output;
my $cookie;

# Process actions
if ( $action eq 'clear_gssapi' ) {

	# Clear the GSSAPI preference cookie by setting it to expire
	$cookie = $cgi->cookie(
		-name     => 'oauth_favor_gssapi',
		-value    => '',
		-expires  => '-1d',
		-path     => '/',
		-secure   => 1,
		-httponly => 1,
		-samesite => 'Lax'
	);

	$output = $logoff->generate_confirmation_page('clear_gssapi');

} elsif ( $action eq 'logoff' ) {

	# Clear the session cookie by setting it to expire
	$cookie = $cgi->cookie(
		-name     => 'oauth_session',
		-value    => '',
		-expires  => '-1d',
		-path     => '/',
		-secure   => 1,
		-httponly => 1,
		-samesite => 'Lax'
	);

	$output = $logoff->generate_confirmation_page('logoff');

} else {

	# Show the logoff page with appropriate buttons
	my $has_gssapi_cookie = $gssapi_cookie && $gssapi_cookie =~ /^(1|true|yes)$/i;
	$output = $logoff->generate_logoff_page($has_gssapi_cookie);
}

# Print header and output
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
