# JazzHands OpenID Interface

This module provides an OpenID connect interface for authenticating via
a backend JazzHands database. It currently handles issuing JWT Bearer tokens
for applications for use with applications that use them.  It currently only
supports the `client_credentials` or `password` grant type.  Hopefully,
it will eventually support tokens.

## TL;DR - How to get it up and running

### Overview

This requires a [JazzHands](https://github.com/jazzhandscmdb/jazzhands) database to be
setup and is installed in a schema collocated with that.

There are two components -- one is the database backend changes, which
is made up of a series of views on top of the JazzHands schema that are
placed in a dedicated schema, named and owned by JazzHands_openid .

The second part is a cgi-script that interacts with that schema to
issue JWTs.  This is provided as a docker container, but it would also be
possible to do this outside of docker based on the container build directions.
For now, it is written in perl although a drop in rewrite in a different
language is expected.

Each service that wants JWTs issued for it needs to be configured and it
typically would be a scope difference.  It is possible for services to share
the same JWT, using the same issuer.

### Installation and Configuration

The software requires the database be configured.

#### Database Configuration

1. Assuming an existing JazzHands install.  There are some assumptions of that install baked into here that are not well documented (such as pgcrypto).
2. Run through all the steps inside `all.sql`.
   * This can be run as SUPERUSER, it assumes roles to minimize risks.
   * It will create the `jazzhands_openid` user and schema (if they do not exist).  This will be the owner of all the views and whatnot created in the schema, and except for schema changes, never logs in.
   * It will make appropriate grants so that the schema work.
   * It will create a user `app_jazzhands_openid_jwt_minter` and give it grants such that it can interact with views as it needs to.
3. Configure service specific endpoints
   * insert `service`, `service_version`, `service_endpoint`
   * insert to `service_relationship` if this is hosted on another service
   * use `signkeymgr.pl` to insert a private key in the database and vault or manually insert into `private_key1 and `property`.
   * create account collections and properties for how to define how users work

#### Example database configuration

```
[cmdbhost#5 ~/jazzhands-openid] psql -U postgres -d cmdb
psql (12.9 (Ubuntu 12.9-0ubuntu0.20.04.1))
Type "help" for help.

postgres@[local]:jazzhands# begin;
BEGIN
postgres@[local]:jazzhands*# \i all.sql
 begin_maintenance
-------------------
 t
(1 row)

SET
Pager usage is off.
psql:database/create_scaffolding.sql:32: NOTICE:  created jazzhands_openid
DO
ALTER ROLE
GRANT
psql:database/create_scaffolding.sql:53: NOTICE:  schema "jazzhands_openid" does not exist, skipping
DO
 ...
GRANT
postgres@[local]:jazzhands*# alter user app_jazzhands_openid_jwt_minter password 'Vv';
postgres@[local]:jazzhands*# commit;
COMMIT;
```

#### Configuring the first service

This involves some direct database manipulation to setup a key pair for
signing and validating JWTs.  The private key is stored in the database (or
better, Hashicorp Vault), and `minter` uses it to issue JWTs.   It is possible
for multiple services to share the same key pair, or for each service to have
its own.   If one claim will have multiple scopes, they will need to share the
same keypair.  (Minter does not issue things like this yet, but it could in
the future).

1. A service needs to exist in the database first:
```
user@cmdbhost:cmdb> insert into service (service_name, service_type) values ('testinator-api', 'network') returning *;
┌────────────┬────────────────┬──────────────┬─────────────┬───────────┬────────────────┬───────────────┬───────────────────────────────┬───────────────┬───────────────┐
│ service_id │  service_name  │ service_type │ description │ is_active │ is_synthesized │ data_ins_user │         data_ins_date         │ data_upd_user │ data_upd_date │
├────────────┼────────────────┼──────────────┼─────────────┼───────────┼────────────────┼───────────────┼───────────────────────────────┼───────────────┼───────────────┤
│       2641 │ testinator-api │ network      │             │ t         │ f              │ kovert        │ 2023-03-01 16:35:13.085194+00 │               │               │
└────────────┴────────────────┴──────────────┴─────────────┴───────────┴────────────────┴───────────────┴───────────────────────────────┴───────────────┴───────────────┘
(1 row)
```
2. There are a number of ways to get the key into the database and vault.  The documentation for signkeymgr contains various ways, but this is an example that uses Kerberos.
```
[host:1 jazzhands-openid] VAULT_CAPATH=/etc/ssl/certs VAULT_ADDR=https://vault.example.org:8200/ save --generate --vaultpath kv/data/minter/testinator --dbhost cmdbhost --database jazzhands --service testinator-api
[host:2 jazzhands-openid]
```
3. Add a service version for the underlying service.  This ideally matches the tag of a release:
```
user@cmdbhost:cmdb> INSERT INTO service_version (service_id, service_version_name)
SELECT service_id, '0.99'
FROM service
WHERE service_type = 'network'
AND service_name IN ('testinator-api') returning *;
┌────────────────────┬────────────┬──────────────┬──────────────────────┬────────────┬───────────────┬────────────────┬───────────────┬──────────────────────────────┬───────────────┬───────────────┐
│ service_version_id │ service_id │ service_type │ service_version_name │ is_enabled │ is_deprecated │ is_synthesized │ data_ins_user │        data_ins_date         │ data_upd_user │ data_upd_date │
├────────────────────┼────────────┼──────────────┼──────────────────────┼────────────┼───────────────┼────────────────┼───────────────┼──────────────────────────────┼───────────────┼───────────────┤
│                  4 │       2641 │ network      │ 0.99                 │ t          │ f             │ f              │ kovert        │ 2023-03-01 16:35:41.08424+00 │               │               │
└────────────────────┴────────────┴──────────────┴──────────────────────┴────────────┴───────────────┴────────────────┴───────────────┴──────────────────────────────┴───────────────┴───────────────┘
(1 row)

INSERT 0 1
```
4. Setup a service endpoint.  This example assumes a DNS record already exists for testinator.example.org (columns in `dns_record` and `dns_domain`):
```
INSERT INTO service_endpoint (
        service_id, dns_record_id, port_range_id, service_endpoint_uri_fragment
) SELECT service_id, dns_record_Id, port_range_id, 'testinator/v1'
FROM service,  port_range,
        (SELECT dns_record_id
		FROM dns_record
		JOIN dns_domain USING (dns_domain_id)
		WHERE dns_name = 'drt-api'
		AND dns_domain_name = 'example.org'
	) x
WHERE service_type = 'network' AND service_name = 'testinator-api'
AND port_range_type = 'services' AND port_range_name = 'https'
;
```
4, The end point needs to be attached to actual devices running the service.
There's a number of ways to do this but to anchor it to one host, something
like this:
```
SELECT service_manip.direct_connect_endpoint_to_device(
        device_id := device_id,
        service_version_id := service_version_id,
        service_endpoint_id := service_endpoint_id,
        service_environment_id := service_environment_id
) FROM device, service_endpoint JOIN (
        SELECT service_id, service_version_id
        FROM service_version sv JOIN service USING (service_id), service_environment
        WHERE service_name IN ('testinator-api')
        AND sv.service_type = 'network'
        AND service_version_name = '0.99'
        AND service_environment_type = 'default'
        AND service_environment_name = 'production'
) sv USING (service_id)
WHERE device_name ~ '01.api.example.org'
AND service_endpoint_id IN (
        SELECT service_endpoint_id
        FROM service_endpoint
        WHERE service_id IN (
                SELECT service_id
                FROM service
                WHERE service_type = 'network'
                AND service_name IN ('testinator-api')
        )
)
```
5. Likely all access should be granted into an account collection type, and it probably should be openid, but create the account collection type:
```
INSERT INTO val_account_collection_type ( account_collection_type) VALUES ( 'openid');
```
5. At this point, no users have access to get tokens, so that access will need to be granted.  Map a user to the negotiate method replace `negotiate` with `password` to allow username/password):
```
WITH ac AS (
    INSERT INTO account_collection (
        account_collection_name, account_collection_type
    ) VALUES (
        'testinator-api-negotiate', 'openid'
    ) RETURNING *
) INSERT INTO property (
    property_type, property_name, service_version_collection_id,
    account_collection_id, property_value_json
) SELECT 'jazzhands-openid', 'authentication-rules', service_version_collection_id,
    account_collection_id, '{"method":"negotiate", "max_token_lifetime": 900 }'
FROM ac, service_version_collection
WHERE service_version_collection_name = 'testinator-api'
AND service_version_collection_type = 'current-services';
```
6. Add membership to that account collection:
```
INSERT INTO account_collection_hier (
    account_collection_id, child_account_collection_id
) SELECT p.account_collection_id, c.account_collection_id
FROM (
    SELECT *
    FROM account_collection
    WHERE account_collection_type = 'openid'
    AND account_collection_name = 'testinator-api-negotiate'
) p, (
    SELECT *
    FROM account_collection
    WHERE account_collection_type = 'team'
    AND account_collection_name IN (
        'Some Team'
    )
) c;
```

#### Software Installation

This installs the minter web service in a docker container.
It needs to run under apache in order for Kerberos/negotiate to work or
some other browser that has an implementation.  It was untested under
anything else.  The expectation is that there will probably be a front end
that forwards into the container, although this is not strictly necessary.

##### Docker Configuration

1. The Dockerfile in the minter directory builds a container that can be installed and configured.
2. The docker-compose.yaml file describes how to set it up.
    * Volumes mounted from outside onto paths inside the container:
        1. `/etc/keytab.www` - keytab with HTTP/fqdn for the possible ways the service can be connected to.  This is used for any users (and devices`) that use Kerberos to authenticate
        2. `/var/lib/jazzhands/appauthal-info/oauth-jwt-minter.json` - DBAAL file for the `app_jazzhands_openid_jwt_minter` connection setup in the next steps.
        3. `/vault` - contains files, role-id and secret-id that are refreshed periodically to allow for connecting to vault to retrieve private keys (or anything else)
        4. `/etc/ssl/certs` - where various things expect trusted certificates to live for validating any https connections

    * Environment Variables
        1. APPAUTHAL_CONFIG can be a path to a config file to override the default place for appauthal files
        2. VAULT_ADDR can be used to define where vault is, if it's not in the dbaal file
        3. VAULT_CAPATH can be used to define where to look for the CA for connecting to vault, if it is not in the dbaal file
        4. There are other variables used by the underlying tools and libraries that can be tweaked

##### Front End Configuration

* For apache.   The /token endpoint will take care of redirecting to the `/n/` endpoint if Kerberos/GSSAPI/Negotiate is required for the user.  The `/n` endpoint is just protected by Kerberos.  If Kerberos is not used, then the first stanza is needed.
```
ProxyPass /token/ http://127.0.0.1:8080/token/
ProxyPassReverse /token/ http://127.0.0.1:8080/token/

ProxyPass /n/ http://127.0.0.1:8080/n/
ProxyPassReverse /n/ http://127.0.0.1:8080/n/
```

* Nginx would be similar.  As with apache `/n` is only required if kerberos/negotiate is in play.
```
  location ~ ^(/token/|/n/) {
    proxy_pass            http://127.0.0.1:8080/$1;
    proxy_read_timeout    90s;
    proxy_connect_timeout 90s;
    proxy_send_timeout    90s;
    proxy_set_header      Host $host;
    proxy_set_header      X-Real-IP $remote_addr;
    proxy_set_header      X-Forwarded-For $proxy_add_x_forwarded_for;
  }
```

## Implementation

#### Database Configuration for Services that have issued JWTs.

The following properties (property_type:property_name) are used to define how access works:

`service_version_collection_id` is set for all of them, typically to the
collection of type `current_services` named after the service.

Default lifetime for a bearer token is 3600 seconds (one hour).

* property jazzhands-openid:jwt-signer - set by `signkeymgr.pl`.
    * `service_version_collection_id` (as above)
    * `property_value_private_key`
* property `jazzhands-openid:authentication-rules`
    * `service_version_collection_id` (as above)
    * `account_collection_id` - who it applies to
    * `property_value_json` - with the following keys, only method is required:
        * *method* can be `negotiate` or `password` . Negotiate will force Kerberos using the `client_credentials` type, `password` will look up the user's blowfish password in `account_password`
        * *prefix*, optional, is the database username that should be prepended to the user  as the user to act as.  Such as "prst_."  When left out, the user's role is assumed.
        * *suffix*, optional, is the database username that should be appended to the user  as the user to act as.  Such as "_pgrst."  When left out, the user's role is assumed.
        * *max_token_lifetime* - optional, number of seconds a token can be issued for to the user
* property `jazzhands-openid:permit-device-authentication` - defines what devices are allowed to authenticate to the API using their Kerberos principal and what role they are to assume
    * `service_version_collection_id` (as above)
    * `device_collection_id` - devices that are allows to authenticate
    * `property_value_json`, with the following keys, only role is required:
        * *role*: role to assume for this device
        * *max_token_lifetime* - optional, number of seconds a token can be issued for to the user
* property `jazzhands-openid:act-as-device` - allow humans to authenticate as themselves but act on behalf of a device
    * `service_version_collection_id` (as above)
    * `account_collection_id` - who is allowed to do this
    * `device_collection_id` - devices that are allows to be authenticated
* property `jazzhands-openid:act-as-account` and related.  This is kind of gross, but is multiple properties that act in concert with each other.  This will hopefully eventually be replaced with one uber property when json+fk support is better:
   *  property `jazzhands-openid:act-as-account` - allow an account to assume the permissions of a different account
        * `service_version_collection_id` (as above)
        * `account_collection_id` - who is allowed to do this
        * `property_value_account_collection_id` - whose identity they can assume
   *  property `jazzhands-openid:act-as-account-prefix` - prefix, as with `authentication-rules`
        * `service_version_collection_id` (as above)
        * `account_collection_id` - who is allowed to do this
        * `property_value` - prefix to use
   *  property `jazzhands-openid:act-as-account-suffix` - suffix, as with `authentication-rules`
        * `service_version_collection_id` (as above)
        * `account_collection_id` - who is allowed to do this
        * `property_value` - suffix to use


## Architecture

### Summary

This was originally created to support generating JWTs for use with
[PostgREST](https://postgrest.org) to provide an API interface to
obtaining a JWT for use with it and in the interest of standards
compliance, became a generic JWT issuer and ultimately something that
can be used by anything that wants to hook into OpenID connect.

It is, however, primarily to support PostgREST instances, so there's some
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

## Implementation

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
be passed into the requests to the PostgREST endpoints:
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
* In the case that a given services is hosted on another one, an entry in **`service_relationship`**
* A **`private_key`** to sign JWTs and a **`property`** that ties it a **`service_version_collection`** (typically one of the auto created ones)
* **`account_collection`s** , and **`property`s**  grant user(s) the ability to login.  Logically, this would be a type per ecosystem, such as type
`PostgREST-support` although that is not required.

