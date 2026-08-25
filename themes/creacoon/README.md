# Creacoon theme

Adds a signed jump-link route so documentation pages can be linked from another
application, with the visitor arriving already logged in as a single read-only
BookStack user.

## Why a theme and not core changes

The route is registered through `ThemeEvents::ROUTES_REGISTER_WEB`, which hands
over the router inside the `web` middleware group without `auth`. No BookStack
core file is modified, so upgrades stay clean.

## Setup

1. Set `APP_THEME=creacoon`.
2. Create a BookStack user for link visitors and give it a role with view-only
   permission on the shelves that should be reachable. Its permissions are the
   real security boundary, not the token.
3. Set `DOCS_JUMP_USER` to that user's email address.
4. Set `DOCS_JUMP_SECRET` to a long random string, shared with the linking
   application.

With either variable empty the route returns 503, so the theme is inert until
deliberately configured.

## Link format

    GET /sso/jump?d=<base64url-payload>&s=<hmac-sha256-of-payload>

Payload, before base64url encoding:

```json
{
  "exp": 1717070000,
  "nonce": "16-random-chars",
  "to": "/books/handbook/page/getting-started"
}
```

Generating side, in the linking Laravel application:

```php
$payload = rtrim(strtr(base64_encode(json_encode([
    'exp'   => time() + 60,
    'nonce' => Str::random(16),
    'to'    => '/books/handbook/page/getting-started',
])), '+/', '-_'), '=');

$url = 'https://docs.example.com/sso/jump?d=' . $payload
    . '&s=' . hash_hmac('sha256', $payload, config('services.docs_jump.secret'));
```

Build the URL when the page is rendered, not when it is cached. A 60 second
token baked into a cached page is a dead link.

## Security properties

The token travels in a URL, so it reaches browser history, `Referer` headers on
outbound links, and any proxy log in between. Two things contain that:

- **Short expiry.** `exp` is checked against server time. Keep it around 60
  seconds; do not stretch it for convenience.
- **One-time use.** `nonce` is recorded in the cache for 5 minutes and a repeat
  is rejected, so a captured link cannot be replayed.

Three limits worth knowing:

- The session outlives the token. After the jump the visitor holds a normal
  BookStack session and can browse anything the service user can see.
- All views are attributed to one account, so there is no per-person audit
  trail. Per-user identity would mean a real OIDC provider instead.
- Already-authenticated visitors are redirected without touching their session.
  Without that guard, a staff member logged in via Google would be silently
  downgraded to the read-only user and lose edit rights mid-session.
