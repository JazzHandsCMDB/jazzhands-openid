# JazzHands OpenID Interface

This module provides an OpenID connect interface for authenticating via
a backend JazzHands database.  It was originally created to support
generating JWTs for use with [PostgREST](https://postgrest.org) to provide
an API interface to obtaining a JWT for use with it and in the interest of
standards compliance, became a generic JWT issuer and ultimately something
that can be used by anything that wants to hook into OpenID connect.

It is, however, primarily to support postgrest instances, so there's some
hard coded nuances related to that, but the goal is to move away from that
as much as possible and make that just another use case.

This module provides all the components to setup an endpoint and manage
various ways for users to obtain a JWT.

This just takes care of authenticating a user and setting up appropriate
access, be that a JWT to be used as a bearer token for access or,
eventually, the code/token dance for an end user to authenticate to a service.

The general interface is kind of clunky and probably needs a PostgREST
interface to make better, which would lead to a chicken/egg thing, but
that's life.

### JazzHands Integration

This support provides an [OAuth2/OpenID-Connect style](https://www.rfc-editor.org/rfc/rfc6749.html) web interface for
issuing limited life JWTs that are used as bearer tokens.  They are
issued and then forgotten, so it is not possible to preemptively expire
them, thus limited lifetime.  OAuth2 has "scopes" which are named after
service endpoints.

## JWT / Bearer Token Support

The JWT is encoded as a bearer token which is really a base64 encoded
signed JWT to authenticate users.  The JWT contains various pieces about
the user that will be used underneath and tells how to authenticate as
the user.

There's very little code in all of this.  Most of it is JWT management
and conventions.

### database schema

The database schema has a handful of views that present all the various
scenarios:

* **authentication_rules** - This specifies the methods a user can use to login and how to translate their name.   The current supported methods are negotiate and password.  In the future, it may be desire to add TLS authentication
* **permitted_account_impersonation** - Maps services to users that can impersonate other users (login on behalf of) and what their assumed role should be when signing in.  The human still needs to be able to login based on authentication_rules but the role assumed is the one assumed.  That means that a user does not need to be able to login directly in order to have their identity assumed.
* **permitted_device_impersonation** - services/user/device mapping for which humans are allowed to simulate which devices.  This uses the role mapping defined in service_device_permitted_authentication for what role to assumed.
* **service_device_permitted_authentication** - service/device mappings and the database role that should be assumed (using host/fqdn Kerberos principals, typically but they could also use user/pass)
* **service_jwt_signing_keys** - given a service, the location (ideally in vault) of the key used to sign JWTs for the services.

Most of these are views on top of the `property`, `account_collection`,
and `service_version_collection` and related tables.

### minter

minter is a web service that issues JWTs using an
[OAuth2/OpenID-Connect style](https://www.rfc-editor.org/rfc/rfc6749.html)
compatible interface.   It takes a JSON blob as input and returns a JSON
blob with errors or a bearer token and related data.

Two types of oauth2 methods for login are supported,
"client_credentials" and "password".  In the "client_credentials"
case, the web server handles the authentication and passes the identity
down.  The only client_credentials case supported is negotiate, which
is basically a way of doing GSSAPI/Kerberos with web interfaces.  It
would be possible to extend this to include client TLS or other methods.
Basic AUTH (back ended with LDAP) would not make any sense since oauth2
provides a username/password method.

For password authentication, the `account_password_manip.authenticate_account`
function is used to authenticate a user, wrapping the password in the
`obfuscation_tools` library so passwords don't leak in function arguments if
query logging is turned up a lot.  This means that the password used for the
user is the one in the JazzHands `account_password` table and *NOT* a database
user password, despite the user having an account.  In general the user used
for these logs should be separate than a direct user login.

The permitted methods are stored in `authentication_rules` as well as
optional translations from the underlying username to the role to sign into the
database as.  This means that humans that have general use accounts with
broad permissions that do not overlap "api" accounts.  This extra layer of
indirection can be excessive for pseudousers that only connect via the API
so it is not required/recommended.

Note that if a user attempts "client_credentials" and the username and password
are passed in, the authentication will outright fail in order to prevent
credentials leak.

If a user is setup to use the negotiate extension, the minter itself
takes care of sending back a `WWW-Authenticate: Negotiate` header which
should kick off GSSAPI if the client supports it, re-invoking minter
after the web server has processed the headers and authenticated the
user.  It does a "look ahead" at what was posted to determine if this
should happen and assumes the client will POST the same payload after
authentication starts (which typically happens).  Adding client TLS
support would require figuring out how to deal with this look ahead, if
possible (it may just outright fail).

### Request Cycle

#### Request format

An https POST of type application/x-www-form-urlencoded using the following
values:

```
                grant_type    => 'client_credentials  or password',
                username     => 'unmapped username',
                password => 'user password',
                nonce => 'some nonce'
                scope => 'https://myapi.example.com/api/v1',
                on_behalf_of => 'someone else',
```

It is also possible to set on_behalf_of to `host/fqdn`, which will cause
device impersonation to take place, if permitted.

The minimum required are `grant_type`, `nonce`, and `scope`.  If `grant_type` is
`password`, then `username` and `password` are also required.

#### minter response

A successful response if code 200 includes a json response of:

```
{
  "scope": "https://myapi.example.com/api/v1"",
  "token_type": "Bearer",
  "access_token": "base64string",
  "expires_in": "900"
}
```

The only token type currently supported is `Bearer`, and any other value
should cause the client to error out.  The value of `access_token` should
be passed into the requests to the postgrest endpoints:
```
Authorization: Bearer $access_token
```

When using with PostgREST, the The scope becomes the audience inside the
bearer token, which is validated by PostgREST.

#### minter errors

Error responses should be
[Consistent with the OAuth spec](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1).

Failures will be 400s and the body will always be a json message
with a specific `error` field and a human readable `error_description`
value and type 400.  A non-400 response (besides the 401 Unauthorized to
trigger the GSSAPI/Negotiate dance) means there is a problem outside minter
causing things to fail.  Database connection errors and other transient
errors, will show up as 400s with `temporary_unavailable` error codes, and there
will be more information for the operator in the error output of the
minter process  (typically the apache logs or the container foreground
logs).

### Mapping Usernames

It is possible to map JazzHands accounts to database users 1:1 with the same
name.  It is also possible to setup prefixes and suffixes for the user that
gets the role set.   For example, given a prefix of pgst_, if user `kovert`
signed in as themselves, they would be mapped to the `pgrst_kovert`.  This can
be assigned on a per-account collection basis, so it is possible to have one
policy assigned to humans, who may have different account permissions and
another to pseudousers.

It is possible to allow users to assume the identity of other users if they
are marked as such.  In that case, it is possible to set a prefix and suffix
for _all_ users setup this way.  This will hopefully be addressed in a future
version so it is as granular as the per-individual system.

#### JWT format

The possible values that minter may include are as follows (with a note to
when they are part of the JWT):

```
{
  "ist" : epoch,                          # time_t when issued, always
  "sub" : "who to log",                   # subject, humans, always
  "jti" : "UUID",                         # correlate to logs, always
  "act" : {                               # only if issued on behalf
      "sub" : "kovert"                    # who asked for it
  },
  "aud" : "URL",                          # scope/audience, URL, always
  "role" : "who to become",               # PostgREST assumes this, always
  "iss" : "4b3a867cabeb_oauthminter",     # issuer id (hostname, etc), always
  "exp" : epoch,                          # when expired, always
  "nbf" : epoch                           # when issued, always
}
```


"role" is "sub" passed through the aforementioned mapping processes.  This is
the database user that is ultimately `SET LOCAL ROLE`d to.  This will
eventually be configurable per-service.

"sub" is a JazzHands `account`.  The "act" section only exists if
the JWT was grabbed on behalf of another account and would be the user that
authenticated to get the JWT (unmapped).  IF there is not "act" section, then
the subject

There is no support for refresh tokens at this time.
Document:

* how errors look and what responses look like.
* on_behalf_of to the request (I think) and device_id to the JWT.

#### JazzHands Logging

Need to flesh this out and finish.  Basically, logging all the minted
tokens such that they get stored somewhere centrally.

## Database Configuration

There need to be some stored procedures for the generic part of things.

This implementation depends on certain service model to exist for the api.
This may be inside another service.   Each service uses a private key to
sign JWTs that are scoped to the API.  It is possible for services to share the
key and for one JWT to handle multiple scopes/audiences although minter
does not support this at this time.

The following need to exist:
* A **`service`** row for the service itself
* At least one **`service_version`** for the service.  Ideally this is something that gets updated over time but it's possible to have just a stub for all versions.
* I the case that a given services is hosted on another one, an entry in **`service_relationship`**
* A **`private_key``** to sign JWTs and a **`property`** that ties it a **`service_version_collection`** (typically one of the auto created ones)
* **`account_collection`s** , and **`property`s**  grant user(s) the ability to login.  Logically, this would be a type per ecosystem, such as type
`postgrest-support` although that is not required.

Once those are created, the roles and special grants whatnot can be setup:

