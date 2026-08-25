<?php

use BookStack\Access\LoginService;
use BookStack\Facades\Theme;
use BookStack\Theming\ThemeEvents;
use BookStack\Users\Models\User;
use Dotenv\Dotenv;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/*
 * BookStack `require`s this file rather than `require_once`, and one process can
 * boot the application more than once (`artisan config:cache` does), so every
 * declaration below has to tolerate being reached twice.
 *
 * The listener registration at the bottom is deliberately left unguarded: each
 * application instance gets its own ThemeService and needs the route.
 */

if (! defined('DOCS_JUMP_NONCE_TTL')) {
    define('DOCS_JUMP_NONCE_TTL', 300);
}

if (! function_exists('docsJumpClients')) {
    /**
     * Read a value that lives in .env rather than in a config file.
     *
     * When the deployment caches config, Laravel skips loading .env entirely
     * (LoadEnvironmentVariables::bootstrap returns early), so env() comes back
     * empty at runtime even though the value is set. Parse the file directly in
     * that case, and hold the result for the rest of the request.
     */
    function docsJumpEnvValue(string $key): string
    {
        static $parsed = null;

        $value = strval(env($key, ''));

        if ($value !== '') {
            return $value;
        }

        if (is_null($parsed)) {
            $parsed = [];

            try {
                $path = base_path('.env');

                if (is_readable($path)) {
                    $parsed = Dotenv::parse(strval(file_get_contents($path)));
                }
            } catch (\Throwable $exception) {
                Log::warning("Could not read .env for documentation jump config: {$exception->getMessage()}");
            }
        }

        return strval($parsed[$key] ?? '');
    }

    /**
     * Registered linking applications, keyed by client id.
     *
     * Read from the DOCS_JUMP_CLIENTS environment variable, which holds a JSON
     * object of {"client-id": {"secret": "...", "user": "..."}} entries.
     *
     * @return array<string, array{secret: string, user: string}>
     */
    function docsJumpClients(): array
    {
        $raw = docsJumpEnvValue('DOCS_JUMP_CLIENTS');

        if ($raw === '') {
            return [];
        }

        $clients = json_decode($raw, true);

        if (! is_array($clients)) {
            return [];
        }

        return array_filter($clients, function (mixed $client): bool {
            return is_array($client) && ! empty($client['secret']) && ! empty($client['user']);
        });
    }

    /**
     * @return ?array{secret: string, user: string}
     */
    function docsJumpClient(string $clientId): ?array
    {
        return docsJumpClients()[$clientId] ?? null;
    }

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
}

Theme::listen(ThemeEvents::ROUTES_REGISTER_WEB, function (Router $router): void {
    $router->get('/sso/jump', function (Request $request, LoginService $loginService) {
        if (docsJumpClients() === []) {
            abort(503);
        }

        $clientId = strval($request->query('c', ''));
        $client = docsJumpClient($clientId);

        if (is_null($client)) {
            abort(403);
        }

        $payload = strval($request->query('d', ''));
        $signature = strval($request->query('s', ''));

        if (! docsJumpSignatureValid($payload, $signature, $client['secret'])) {
            abort(403);
        }

        $data = docsJumpDecodePayload($payload);

        if (is_null($data)) {
            abort(403);
        }

        if (strval($data['aud'] ?? '') !== $clientId) {
            abort(403);
        }

        if (intval($data['exp'] ?? 0) < time()) {
            abort(403);
        }

        $nonce = strval($data['nonce'] ?? '');

        if ($nonce === '' || ! Cache::add("docs-jump:{$clientId}:{$nonce}", true, DOCS_JUMP_NONCE_TTL)) {
            abort(403);
        }

        $target = docsJumpSafeTarget($data['to'] ?? '/');

        if (auth()->check()) {
            return redirect($target);
        }

        $serviceUser = User::query()->where('email', '=', $client['user'])->first();

        if (is_null($serviceUser)) {
            Log::error("Documentation jump client \"{$clientId}\" names a BookStack user that does not exist: {$client['user']}");

            abort(500);
        }

        $loginService->login($serviceUser, "docs-jump:{$clientId}");

        return redirect($target);
    })->name('docsJump');
});
