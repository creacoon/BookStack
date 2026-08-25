<?php

use BookStack\Access\LoginService;
use BookStack\Facades\Theme;
use BookStack\Theming\ThemeEvents;
use BookStack\Users\Models\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Cache;

const DOCS_JUMP_NONCE_TTL = 300;

function docsJumpDecodePayload(string $payload): ?array
{
    $decoded = base64_decode(strtr($payload, '-_', '+/'), true);

    if ($decoded === false) {
        return null;
    }

    $data = json_decode($decoded, true);

    return is_array($data) ? $data : null;
}

function docsJumpSignatureValid(string $payload, string $signature, string $secret): bool
{
    return hash_equals(hash_hmac('sha256', $payload, $secret), $signature);
}

function docsJumpSafeTarget(mixed $target): string
{
    if (! is_string($target) || ! str_starts_with($target, '/') || str_starts_with($target, '//')) {
        return '/';
    }

    return $target;
}

Theme::listen(ThemeEvents::ROUTES_REGISTER_WEB, function (Router $router): void {
    $router->get('/sso/jump', function (Request $request, LoginService $loginService) {
        $secret = env('DOCS_JUMP_SECRET');
        $serviceUserEmail = env('DOCS_JUMP_USER');

        if (empty($secret) || empty($serviceUserEmail)) {
            abort(503);
        }

        $payload = strval($request->query('d', ''));
        $signature = strval($request->query('s', ''));

        if (! docsJumpSignatureValid($payload, $signature, $secret)) {
            abort(403);
        }

        $data = docsJumpDecodePayload($payload);

        if (is_null($data)) {
            abort(403);
        }

        if (intval($data['exp'] ?? 0) < time()) {
            abort(403);
        }

        $nonce = strval($data['nonce'] ?? '');

        if (empty($nonce) || ! Cache::add("docs-jump:{$nonce}", true, DOCS_JUMP_NONCE_TTL)) {
            abort(403);
        }

        $target = docsJumpSafeTarget($data['to'] ?? '/');

        if (auth()->check()) {
            return redirect($target);
        }

        $serviceUser = User::query()->where('email', '=', $serviceUserEmail)->first();

        if (is_null($serviceUser)) {
            abort(503);
        }

        $loginService->login($serviceUser, 'docs-jump');

        return redirect($target);
    })->name('docsJump');
});
