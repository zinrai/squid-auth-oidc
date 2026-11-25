# squid-auth-oidc

A Squid Basic authentication helper that accepts an OIDC ID token as the proxy
password. The login must equal a claim of the token, so `%ul` in Squid's
access log names the person the token was issued to, and the token's groups
come back as annotations for `note` ACLs.

It is built for one issuer and one audience.
The client side is [proxy-relay-oidc](https://github.com/zinrai/proxy-relay-oidc),
which logs in and puts the token in `Proxy-Authorization`, and
[squid-auth-oidc-lab](https://github.com/zinrai/squid-auth-oidc-lab) runs the
two together with Dex.

## Install

Download the binary for your architecture from the
[releases](https://github.com/zinrai/squid-auth-oidc/releases).
`squid-auth-oidc -version` prints which release it is.

## Squid configuration

```
https_port 3129 tls-cert=/etc/squid/tls/server.crt tls-key=/etc/squid/tls/server.key

auth_param basic program /usr/local/libexec/squid-auth-oidc -issuer https://dex.example.com/dex -client-id squid-relay -username-claim preferred_username
auth_param basic children 5
auth_param basic realm forward-proxy
auth_param basic credentialsttl 1 minute
auth_param basic casesensitive on

acl authenticated proxy_auth REQUIRED
acl grp_admins note groups_ admins
acl to_internal dstdomain .internal.example.com

http_access deny !authenticated
http_access allow grp_admins to_internal
http_access deny all

logformat auth %ts.%03tu %>a %Ss/%03>Hs %rm %ru %ul %{groups_}note
access_log stdio:/var/log/squid/access.log auth
```

`https_port`, not `http_port`: the token is a bearer credential, and in clear
text anyone on the path could replay it until it expires. Give the port a
certificate its clients trust. After each renewal, load the new certificate
without restarting Squid:

```
squid -k reconfigure
```

| Flag | Meaning |
|------|---------|
| `-issuer` | Issuer URL. https only |
| `-client-id` | The `aud` the token must carry |
| `-username-claim` | Claim that must equal the proxy login, such as `preferred_username` or `email` |

All three are required. Do not set `concurrency=` on the helper; a request
line with a channel ID is answered `BH`.

The issuer's certificate is checked against the system trust store. For a
private CA, point `SSL_CERT_FILE` at it in Squid's environment; helpers
inherit it.

## Answers

| Answer | When |
|--------|------|
| `OK groups_=<group> ...` | Valid token whose login matches. One `groups_` per group |
| `OK groups_=` | Valid token without groups |
| `ERR` | Bad signature, wrong issuer or audience, expired, login mismatch, unsigned |
| `BH` | The issuer or its key set could not be fetched, or a group name holds a control character |

`groups_` is sent even when empty. Squid merges a helper's annotations into the
credentials it caches per login, so an answer that left the key out would keep
the previous answer's groups. The trailing underscore marks the key as custom
to Squid 7, which otherwise logs a warning for every answer.

Discovery runs on the first request, not at startup, so the helper keeps
running while the issuer is down and answers `BH` until it is back. Keys are
cached; a valid token signed with a cached key is accepted with the issuer
down.

Reasons for `ERR` and `BH` go to stderr, which Squid writes to `cache.log`.
They are not sent as `message=`, which can reach the client.

## Limits

- Squid passes the helper one line of at most 8,192 bytes, login and token
  included. A token with many groups can exceed it; keep the groups claim to
  what the proxy needs.
- Squid caches an `OK` for `credentialsttl`, counted from the helper's answer.
  An expired token keeps working for at most that long.

## License

This project is licensed under the [MIT License](LICENSE).
