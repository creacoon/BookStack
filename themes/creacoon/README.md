# Creacoon theme

Adds a signed jump-link route so documentation pages can be linked from other
applications, with the visitor arriving already logged in as a read-only
BookStack user.

Several applications can be hosted side by side. Each is a *client* with its own
HMAC secret and its own BookStack user, so one application can never mint links
into another's documentation.

## Why a theme and not core changes

The route is registered through `ThemeEvents::ROUTES_REGISTER_WEB`, which hands
over the router inside the `web` middleware group without `auth`. No BookStack
core file is modified, so upgrades stay clean.

## Setup

1. Set `APP_THEME=creacoon`.
2. Per linking application, create a BookStack user and give it a role with
   view-only permission on that application's shelves. These permissions are
   what actually separate one tenant's docs from another's.
3. Generate a long random secret per application.
4. List them all in `DOCS_JUMP_CLIENTS` as a JSON object:

```json
{
  "first-app":  {"secret": "...", "user": "docs-first-app@example.com"},
  "second-app": {"secret": "...", "user": "docs-second-app@example.com"}
}
```

With `DOCS_JUMP_CLIENTS` empty the route returns 503, so the theme is inert
until deliberately configured. Entries missing a `secret` or a `user` are
ignored rather than half-applied.

## Link format

    GET /sso/jump?c=<client-id>&d=<base64url-payload>&s=<hmac-sha256-of-payload>

Payload, before base64url encoding:

```json
{
  "aud": "first-app",
  "exp": 1717070000,
  "nonce": "16-random-chars",
  "to": "/books/first-app/page/getting-started"
}
```

`c` selects which secret verifies the signature. `aud` repeats it inside the
signed payload and is checked against `c`, so a link stays bound to its client
even if two applications are ever misconfigured onto the same secret.

Generating side, in a linking Laravel application:

```php
$payload = rtrim(strtr(base64_encode(json_encode([
    'aud'   => 'first-app',
    'exp'   => time() + 60,
    'nonce' => Str::random(16),
    'to'    => '/books/first-app/page/getting-started',
])), '+/', '-_'), '=');

$url = 'https://docs.example.com/sso/jump?c=first-app&d=' . $payload
    . '&s=' . hash_hmac('sha256', $payload, $secret);
```

Build the URL when the page is rendered, not when it is cached. A 60 second
token baked into a cached page is a dead link.

## Security properties

The token travels in a URL, so it reaches browser history, `Referer` headers on
outbound links, and any proxy log in between. Two things contain that:

- **Short expiry.** `exp` is checked against server time. Keep it around 60
  seconds; do not stretch it for convenience.
- **One-time use.** `nonce` is recorded in the cache for 5 minutes, keyed per
  client, and a repeat is rejected, so a captured link cannot be replayed.

Four limits worth knowing:

- The session outlives the token. After the jump the visitor holds a normal
  BookStack session and can browse anything that client's user can see. Role
  permissions, not the token, are the boundary between tenants.
- All views for one client are attributed to a single account, so there is no
  per-person audit trail. Activity is logged as `docs-jump:<client-id>`, so at
  least the originating application is identifiable.
- Already-authenticated visitors are redirected without touching their session.
  Without that guard, a staff member logged in via Google would be silently
  downgraded to a read-only user and lose edit rights mid-session.
- A leaked secret is limited to its own client, but rotating it means updating
  both `DOCS_JUMP_CLIENTS` here and the linking application's config.
