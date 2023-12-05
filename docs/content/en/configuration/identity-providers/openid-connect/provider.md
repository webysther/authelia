---
title: "OpenID Connect 1.0 Provider"
description: "OpenID Connect 1.0 Provider Configuration"
lead: "Authelia can operate as an OpenID Connect 1.0 Provider. This section describes how to configure this."
date: 2023-05-15T10:32:10+10:00
draft: false
images: []
menu:
  configuration:
    parent: "openid-connect"
weight: 110200
toc: true
aliases:
  - /c/oidc
  - /docs/configuration/identity-providers/oidc.html
---

__Authelia__ currently supports the [OpenID Connect 1.0] Provider role as an open
[__beta__](../../../roadmap/active/openid-connect.md) feature. We currently do not support the [OpenID Connect 1.0] Relying
Party role. This means other applications that implement the [OpenID Connect 1.0] Relying Party role can use Authelia as
an [OpenID Connect 1.0] Provider similar to how you may use social media or development platforms for login.

The [OpenID Connect 1.0] Relying Party role is the role which allows an application to use GitHub, Google, or other
[OpenID Connect 1.0] Providers for authentication and authorization. We do not intend to support this functionality at
this moment in time.

This section covers the [OpenID Connect 1.0] Provider configuration. For information on configuring individual
registered clients see the [OpenID Connect 1.0 Clients](clients.md) documentation.

More information about the beta can be found in the [roadmap](../../../roadmap/active/openid-connect.md) and in the
[integration](../../../integration/openid-connect/introduction.md) documentation.

## Configuration

The following snippet provides a configuration example for the [OpenID Connect 1.0] Provider. This is not
intended for production use it's used to provide context and an indentation example.

```yaml
identity_providers:
  oidc:
    hmac_secret: 'this_is_a_secret_abc123abc123abc'
    issuer_private_keys:
      - key_id: 'example'
        algorithm: 'RS256'
        use: 'sig'
        key: |
          -----BEGIN RSA PUBLIC KEY-----
          MEgCQQDAwV26ZA1lodtOQxNrJ491gWT+VzFum9IeZ+WTmMypYWyW1CzXKwsvTHDz
          9ec+jserR3EMQ0Rr24lj13FL1ib5AgMBAAE=
          -----END RSA PUBLIC KEY----
        certificate_chain: |
          -----BEGIN CERTIFICATE-----
          MIIBWzCCAQWgAwIBAgIQYAKsXhJOXKfyySlmpKicTzANBgkqhkiG9w0BAQsFADAT
          MREwDwYDVQQKEwhBdXRoZWxpYTAeFw0yMzA0MjEwMDA3NDRaFw0yNDA0MjAwMDA3
          NDRaMBMxETAPBgNVBAoTCEF1dGhlbGlhMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
          AK2i7RlJEYo/Xa6mQmv9zmT0XUj3DcEhRJGPVw2qMyadUFxNg/ZFp7aTcToHMf00
          z6T3b7mwdBkCFQOL3Kb7WRcCAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
          JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADQQB8
          Of2iM7fPadmtChCMna8lYWH+lEplj6BxOJlRuGRawxszLwi78bnq0sCR33LU6xMx
          1oAPwIHNaJJwC4z6oG9E_DO_NOT_USE=
          -----END CERTIFICATE-----
          -----BEGIN CERTIFICATE-----
          MIIBWzCCAQWgAwIBAgIQYAKsXhJOXKfyySlmpKicTzANBgkqhkiG9w0BAQsFADAT
          MREwDwYDVQQKEwhBdXRoZWxpYTAeFw0yMzA0MjEwMDA3NDRaFw0yNDA0MjAwMDA3
          NDRaMBMxETAPBgNVBAoTCEF1dGhlbGlhMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
          AK2i7RlJEYo/Xa6mQmv9zmT0XUj3DcEhRJGPVw2qMyadUFxNg/ZFp7aTcToHMf00
          z6T3b7mwdBkCFQOL3Kb7WRcCAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
          JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADQQB8
          Of2iM7fPadmtChCMna8lYWH+lEplj6BxOJlRuGRawxszLwi78bnq0sCR33LU6xMx
          1oAPwIHNaJJwC4z6oG9E_DO_NOT_USE=
          -----END CERTIFICATE-----
    issuer_private_key: |
      -----BEGIN RSA PUBLIC KEY-----
      MEgCQQDAwV26ZA1lodtOQxNrJ491gWT+VzFum9IeZ+WTmMypYWyW1CzXKwsvTHDz
      9ec+jserR3EMQ0Rr24lj13FL1ib5AgMBAAE=
      -----END RSA PUBLIC KEY----
    issuer_certificate_chain: |
      -----BEGIN CERTIFICATE-----
      MIIBWzCCAQWgAwIBAgIQYAKsXhJOXKfyySlmpKicTzANBgkqhkiG9w0BAQsFADAT
      MREwDwYDVQQKEwhBdXRoZWxpYTAeFw0yMzA0MjEwMDA3NDRaFw0yNDA0MjAwMDA3
      NDRaMBMxETAPBgNVBAoTCEF1dGhlbGlhMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
      AK2i7RlJEYo/Xa6mQmv9zmT0XUj3DcEhRJGPVw2qMyadUFxNg/ZFp7aTcToHMf00
      z6T3b7mwdBkCFQOL3Kb7WRcCAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
      JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADQQB8
      Of2iM7fPadmtChCMna8lYWH+lEplj6BxOJlRuGRawxszLwi78bnq0sCR33LU6xMx
      1oAPwIHNaJJwC4z6oG9E_DO_NOT_USE=
      -----END CERTIFICATE-----
      -----BEGIN CERTIFICATE-----
      MIIBWzCCAQWgAwIBAgIQYAKsXhJOXKfyySlmpKicTzANBgkqhkiG9w0BAQsFADAT
      MREwDwYDVQQKEwhBdXRoZWxpYTAeFw0yMzA0MjEwMDA3NDRaFw0yNDA0MjAwMDA3
      NDRaMBMxETAPBgNVBAoTCEF1dGhlbGlhMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
      AK2i7RlJEYo/Xa6mQmv9zmT0XUj3DcEhRJGPVw2qMyadUFxNg/ZFp7aTcToHMf00
      z6T3b7mwdBkCFQOL3Kb7WRcCAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
      JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADQQB8
      Of2iM7fPadmtChCMna8lYWH+lEplj6BxOJlRuGRawxszLwi78bnq0sCR33LU6xMx
      1oAPwIHNaJJwC4z6oG9E_DO_NOT_USE=
      -----END CERTIFICATE-----
    enable_client_debug_messages: false
    minimum_parameter_entropy: 8
    enforce_pkce: 'public_clients_only'
    enable_pkce_plain_challenge: false
    pushed_authorizations:
      enforce: false
      context_lifespan: '5m'
    authorization_policies:
      policy_name:
        default_policy: 'two_factor'
        rules:
          - policy: 'deny'
            subject: 'group:services'
    lifespans:
      access_token: '1h'
      authorize_code: '1m'
      id_token: '1h'
      refresh_token: '90m'
    cors:
      endpoints:
        - 'authorization'
        - 'token'
        - 'revocation'
        - 'introspection'
      allowed_origins:
        - 'https://example.com'
      allowed_origins_from_client_redirect_uris: false
```

## Options

### hmac_secret

{{< confkey type="string" required="yes" >}}

*__Important Note:__ This can also be defined using a [secret](../../methods/secrets.md) which is __strongly recommended__
especially for containerized deployments.*

The HMAC secret used to sign the [JWT]'s. The provided string is hashed to a SHA256 ([RFC6234]) byte string for the
purpose of meeting the required format.

It's __strongly recommended__ this is a
[Random Alphanumeric String](../../../reference/guides/generating-secure-values.md#generating-a-random-alphanumeric-string)
with 64 or more characters.

### issuer_private_keys

{{< confkey type="list(object" required="no" >}}

The list of JWKS instead of or in addition to the [issuer_private_key](#issuerprivatekey) and
[issuer_certificate_chain](#issuercertificatechain). Can also accept ECDSA Private Key's and Certificates.

The default key for each algorithm is is decided based on the order of this list. The first key for each algorithm is
considered the default if a client is not configured to use a specific key id. For example if a client has
[id_token_signed_response_alg](clients.md#idtokensignedresponsealg) `ES256` and [id_token_signed_response_key_id](clients.md#idtokensignedresponsekeyid) is
not specified then the first `ES256` key in this list is used.

#### key_id

{{< confkey type="string" default="<thumbprint of public key>" required="no" >}}

Completely optional, and generally discouraged unless there is a collision between the automatically generated key id's.
If provided must be a unique string with 100 or less characters, with a recommendation to use a length less
than 10. In addition it must meet the following rules:

- Match the regular expression `^[a-zA-Z0-9](([a-zA-Z0-9._~-]*)([a-zA-Z0-9]))?$` which should enforce the following rules:
  - Start with an alphanumeric character.
  - End with an alphanumeric character.
  - Only contain the [RFC3986 Unreserved Characters](https://datatracker.ietf.org/doc/html/rfc3986#section-2.3).

The default if this value is omitted is the first 7 characters of the public key SHA256 thumbprint encoded into
hexadecimal.

#### use

{{< confkey type="string" default="sig" required="no" >}}

The key usage. Defaults to `sig` which is the only available option at this time.

#### algorithm

{{< confkey type="string" default="RS256" required="situational" >}}

The algorithm for this key. This value typically optional as it can be automatically detected based on the type of key
in some situations.

See the response object table in the [integration guide](../../../integration/openid-connect/introduction.md#response-object)
for more information. The `Algorithm` column lists supported values, the `Key` column references the required
[key](#key) type constraints that exist for the algorithm, and the `JWK Default Conditions` column briefly explains the
conditions under which it's the default algorithm.

At least one `RSA256` key must be provided.

#### key

{{< confkey type="string" required="yes" >}}

The private key associated with this key entry.

The private key used to sign/encrypt the [OpenID Connect 1.0] issued [JWT]'s. The key must be generated by the
administrator and can be done by following the
[Generating an RSA Keypair](../../../reference/guides/generating-secure-values.md#generating-an-rsa-keypair) guide.

The key *__MUST__*:

* Be a PEM block encoded in the DER base64 format ([RFC4648]).
* Be either:
  * An RSA private key:
    * Encoded in conformance to the [PKCS#8] or [PKCS#1] specifications.
    * Have a key size of at least 2048 bits.
  * An ECDSA private key:
    * Encoded in conformance to the [PKCS#8] or [SECG1] specifications.
    * Use one of the following elliptical curves:
      * P-256.
      * P-384.
      * P-512.

[PKCS#8]: https://datatracker.ietf.org/doc/html/rfc5208
[PKCS#1]: https://datatracker.ietf.org/doc/html/rfc8017
[SECG1]: https://datatracker.ietf.org/doc/html/rfc5915

If the [certificate_chain](#certificatechain) is provided the private key must include matching public
key data for the first certificate in the chain.

#### certificate_chain

{{< confkey type="string" required="no" >}}

The certificate chain/bundle to be used with the [key](#key) DER base64 ([RFC4648])
encoded PEM format used to sign/encrypt the [OpenID Connect 1.0] [JWT]'s. When configured it enables the [x5c] and [x5t]
JSON key's in the JWKs [Discoverable Endpoint](../../../integration/openid-connect/introduction.md#discoverable-endpoints)
as per [RFC7517].

[RFC7517]: https://datatracker.ietf.org/doc/html/rfc7517
[x5c]: https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
[x5t]: https://datatracker.ietf.org/doc/html/rfc7517#section-4.8

The first certificate in the chain must have the public key for the [key](#key), each certificate in the chain must be
valid for the current date, and each certificate in the chain should be signed by the certificate immediately following
it if present.

### issuer_private_key

{{< confkey type="string" required="yes" >}}

The private key used to sign/encrypt the [OpenID Connect 1.0] issued [JWT]'s. The key must be generated by the
administrator and can be done by following the
[Generating an RSA Keypair](../../../reference/guides/generating-secure-values.md#generating-an-rsa-keypair) guide.

This private key is automatically appended to the [issuer_private_keys](#issuerprivatekeys) and assumed to be for the
`RS256` algorithm. If provided it is always the first key in this list. As such this key is assumed to be the default
for `RS256` if provided.

The issuer private key *__MUST__*:

* Be a PEM block encoded in the DER base64 format ([RFC4648]).
* Be a RSA private key:
  * Encoded in conformance to the [PKCS#8] or [PKCS#1] specifications.
  * Have a key size of at least 2048 bits.

[PKCS#8]: https://datatracker.ietf.org/doc/html/rfc5208
[PKCS#1]: https://datatracker.ietf.org/doc/html/rfc8017

If the [issuer_certificate_chain](#issuercertificatechain) is provided the private key must include matching public
key data for the first certificate in the chain.

### issuer_certificate_chain

{{< confkey type="string" required="no" >}}

The certificate chain/bundle to be used with the [issuer_private_key](#issuerprivatekey) DER base64 ([RFC4648])
encoded PEM format used to sign/encrypt the [OpenID Connect 1.0] [JWT]'s. When configured it enables the [x5c] and [x5t]
JSON key's in the JWKs [Discoverable Endpoint](../../../integration/openid-connect/introduction.md#discoverable-endpoints)
as per [RFC7517].

[RFC7517]: https://datatracker.ietf.org/doc/html/rfc7517
[x5c]: https://datatracker.ietf.org/doc/html/rfc7517#section-4.7
[x5t]: https://datatracker.ietf.org/doc/html/rfc7517#section-4.8

The first certificate in the chain must have the public key for the [issuer_private_key](#issuerprivatekey), each
certificate in the chain must be valid for the current date, and each certificate in the chain should be signed by the
certificate immediately following it if present.

### enable_client_debug_messages

{{< confkey type="boolean" default="false" required="no" >}}

Allows additional debug messages to be sent to the clients.

### minimum_parameter_entropy

{{< confkey type="integer" default="8" required="no" >}}

This controls the minimum length of the `nonce` and `state` parameters.

*__Security Notice:__* Changing this value is generally discouraged, reducing it from the default can theoretically
make certain scenarios less secure. It is highly encouraged that if your OpenID Connect 1.0 Relying Party does not send
these parameters or sends parameters with a lower length than the default that they implement a change rather than
changing this value.

This restriction can also be disabled entirely when set to `-1`.

### enforce_pkce

{{< confkey type="string" default="public_clients_only" required="no" >}}

[Proof Key for Code Exchange](https://datatracker.ietf.org/doc/html/rfc7636) enforcement policy: if specified, must be
either `never`, `public_clients_only` or `always`.

If set to `public_clients_only` (default), [PKCE] will be required for public clients using the
[Authorization Code Flow].

When set to `always`, [PKCE] will be required for all clients using the Authorization Code flow.

*__Security Notice:__* Changing this value to `never` is generally discouraged, reducing it from the default can
theoretically make certain client-side applications (mobile applications, SPA) vulnerable to CSRF and authorization code
interception attacks.

### enable_pkce_plain_challenge

{{< confkey type="boolean" default="false" required="no" >}}

Allows [PKCE] `plain` challenges when set to `true`.

*__Security Notice:__* Changing this value is generally discouraged. Applications should use the `S256` [PKCE] challenge
method instead.

### enable_jwt_access_token_stateless_introspection

{{< confkey type="boolean" default="false" required="no" >}}

Allows [JWT Access Tokens](https://oauth.net/2/jwt-access-tokens/) to be introspected using a stateless model where
the JWT claims have all of the required introspection information, and assumes that they have not been revoked. This is
strongly discouraged unless you have a very specific use case.

A client with an [access_token_signed_response_alg](clients.md#accesstokensignedresponsealg) or
[access_token_signed_response_key_id](clients.md#accesstokensignedresponsekeyid) must be configured for this option to
be enabled.

### pushed_authorizations

Controls the behaviour of [Pushed Authorization Requests].

#### enforce

{{< confkey type="boolean" default="false" required="no" >}}

When enabled all authorization requests must use the [Pushed Authorization Requests] flow.

#### context_lifespan

{{< confkey type="string,integer" syntax="duration" default="5 minutes" required="no" >}}

The maximum amount of time between the [Pushed Authorization Requests] flow being initiated and the generated
`request_uri` being utilized by a client.

### authorization_policies

{{< confkey type="dictionary(object)" required="no" >}}

The authorization policies section allows creating custom authorization policies which can be applied to clients. This
is useful if you wish to only allow specific users to access specific clients i.e. RBAC. It's generally recommended
however that users rely on the [OpenID Connect 1.0] relying party to provide RBAC controls based on the available
claims.

Each policy applies one of the effective policies which can be either `one_factor` or `two_factor` as per the standard
policies, or also the `deny` policy which is exclusively available via these configuration options.

Each rule within a policy is matched in order where the first fully matching rule is the applied policy. If the `deny`
rule is matched the user is not asked for consent and it is considered a rejected consent and returns an
[OpenID Connect 1.0] `access_denied` error.

The key for the policy itself is the name of the policy, which is used when configuring the client
[authorization_policy](clients.md#authorizationpolicy) option. In the example we name the policy `policy_name`.

#### default_policy

{{< confkey type="string" default="two_factor" required="no" >}}

The default effective policy of none of the rules are able to determine the effective policy.

#### rules

{{< confkey type="list(object)" required="yes" >}}

The list of rules which this policy should consider when choosing the effective policy. This must be included for the
policy to be considered valid.

##### policy

{{< confkey type="string" default="two_factor" required="no" >}}

The policy which is applied if this rule matches. Valid values are `one_factor`, `two_factor`, and `deny`.

##### subject

{{< confkey type="list(string(string))" required="yes" >}}

The subjects criteria as per the [Access Control Configuration](../../security/access-control.md#subject). This must be
included for the rule to be considered valid.

### lifespans

Token lifespans configuration. It's generally recommended keeping these values similar to the default values and to
utilize refresh tokens. For more information read this documentation about the [token lifespan].

#### access_token

{{< confkey type="string,integer" syntax="duration" default="1 hour" required="no" >}}

The default maximum lifetime of an access token.

#### authorize_code

{{< confkey type="string,integer" syntax="duration" default="1 minute" required="no" >}}

The default maximum lifetime of an authorize code.

#### id_token

{{< confkey type="string,integer" syntax="duration" default="1 hour" required="no" >}}

The default maximum lifetime of an ID token.

#### refresh_token

{{< confkey type="string,integer" syntax="duration" default="1 hour 30 minutes" required="no" >}}

The default maximum lifetime of a refresh token. The refresh token can be used to obtain new refresh tokens as well as
access tokens or id tokens with an up-to-date expiration.

A good starting point is 50% more or 30 minutes more (which ever is less) time than the highest lifespan out of the
[access token lifespan](#accesstokenlifespan) and the [id token lifespan](#idtokenlifespan). For instance the default for all of these is 60 minutes,
so the default refresh token lifespan is 90 minutes.

#### custom

{{< confkey type="dictionary(object)" required="no" >}}

The custom lifespan configuration allows customizing the lifespans per-client. The custom lifespans must be utilized
with the client [lifespan](clients.md#lifespan) option which applies those settings to that client. Custom lifespans
can be configured in a very granular way, either solely by the token type, or by the token type for each grant type.
If a value is omitted it automatically uses the next value in the precedence tree. The tree is as follows:

1. Custom by token type and by grant.
2. Custom by token type.
3. Global default value.

The key for the custom lifespan itself is the name of the lifespan, which is used when configuring the client
[lifespan](clients.md#lifespan) option. In the example we name the lifespan `lifespan_name`.

##### Example

The following is an exhaustive example of all of the options available. Each of these options must follow all of the
same rules as the [access_token](#accesstoken), [authorize_code](#authorizecode), [id_token](#idtoken), and
[refresh_token](#refreshtoken) global default options. The global lifespan options are included for reference purposes.

```yaml
identity_providers:
  oidc:
    lifespans:
      access_token: '1h'
      authorize_code: '1m'
      id_token: '1h'
      refresh_token: '90m'
      custom:
        lifespan_name:
          access_token: '1h'
          authorize_code: '1m'
          id_token: '1h'
          refresh_token: '90m'
          grants:
            authorize_code:
              access_token: '1h'
              authorize_code: '1m'
              id_token: '1h'
              refresh_token: '90m'
            implicit:
              access_token: '1h'
              authorize_code: '1m'
              id_token: '1h'
              refresh_token: '90m'
            client_credentials:
              access_token: '1h'
              authorize_code: '1m'
              id_token: '1h'
              refresh_token: '90m'
            refresh_token:
              access_token: '1h'
              authorize_code: '1m'
              id_token: '1h'
              refresh_token: '90m'
            jwt_bearer:
              access_token: '1h'
              authorize_code: '1m'
              id_token: '1h'
              refresh_token: '90m'
```

### cors

Some [OpenID Connect 1.0] Endpoints need to allow cross-origin resource sharing, however some are optional. This section allows
you to configure the optional parts. We reply with CORS headers when the request includes the Origin header.

#### endpoints

{{< confkey type="list(string)" required="no" >}}

A list of endpoints to configure with cross-origin resource sharing headers. It is recommended that the `userinfo`
option is at least in this list. The potential endpoints which this can be enabled on are as follows:

* authorization
* pushed-authorization-request
* token
* revocation
* introspection
* userinfo

#### allowed_origins

{{< confkey type="list(string)" required="no" >}}

A list of permitted origins.

Any origin with https is permitted unless this option is configured or the
[allowed_origins_from_client_redirect_uris](#allowedoriginsfromclientredirecturis) option is enabled. This means
you must configure this option manually if you want http endpoints to be permitted to make cross-origin requests to the
[OpenID Connect 1.0] endpoints, however this is not recommended.

Origins must only have the scheme, hostname and port, they may not have a trailing slash or path.

In addition to an Origin URI, you may specify the wildcard origin in the allowed_origins. It MUST be specified by itself
and the [allowed_origins_from_client_redirect_uris](#allowedoriginsfromclientredirecturis) MUST NOT be enabled. The
wildcard origin is denoted as `*`. Examples:

```yaml
identity_providers:
  oidc:
    cors:
      allowed_origins: "*"
```

```yaml
identity_providers:
  oidc:
    cors:
      allowed_origins:
        - "*"
```

#### allowed_origins_from_client_redirect_uris

{{< confkey type="boolean" default="false" required="no" >}}

Automatically adds the origin portion of all redirect URI's on all clients to the list of
[allowed_origins](#allowed_origins), provided they have the scheme http or https and do not have the hostname of
localhost.

### clients

See the [OpenID Connect 1.0 Registered Clients](clients.md) documentation for configuring clients.

## Integration

To integrate Authelia's [OpenID Connect 1.0] implementation with a relying party please see the
[integration docs](../../../integration/openid-connect/introduction.md).

[token lifespan]: https://docs.apigee.com/api-platform/antipatterns/oauth-long-expiration
[OpenID Connect 1.0]: https://openid.net/connect/
[Token Endpoint]: https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
[JWT]: https://datatracker.ietf.org/doc/html/rfc7519
[RFC6234]: https://datatracker.ietf.org/doc/html/rfc6234
[RFC4648]: https://datatracker.ietf.org/doc/html/rfc4648
[RFC7468]: https://datatracker.ietf.org/doc/html/rfc7468
[RFC6749 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
[PKCE]: https://datatracker.ietf.org/doc/html/rfc7636
[Authorization Code Flow]: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
[Subject Identifier Type]: https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
[Pairwise Identifier Algorithm]: https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg
[Pushed Authorization Requests]: https://datatracker.ietf.org/doc/html/rfc9126
