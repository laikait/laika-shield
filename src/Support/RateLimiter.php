<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Support;

/**
 * Class RateLimiter
 *
 * A simple file-based rate limiter. Stores hit counts and windows in
 * PHP's system temp directory — no Redis or database required.
 *
 * For high-traffic production use, swap the storage backend by extending
 * this class and overriding {@see get()} and {@see put()}.
 *
 * @package Laika\Shield\Support
 */
class RateLimiter
{
    private string $storageDir;

    public function __construct(?string $storageDir = null)
    {
        $this->storageDir = rtrim($storageDir ?? sys_get_temp_dir(), '/') . '/laika_shield_rl';

        if (!is_dir($this->storageDir)) {
            mkdir($this->storageDir, 0700, true);
        }
    }

    /**
     * Increment the hit counter for the given key and check whether the limit is exceeded.
     *
     * @param  string $key        Unique identifier (e.g. "rl_192.168.1.1").
     * @param  int    $maxHits    Maximum allowed hits within the window.
     * @param  int    $windowSecs Window size in seconds.
     * @return bool               True if limit is exceeded, false if still within limits.
     */
    public function tooMany(string $key, int $maxHits, int $windowSecs): bool
    {
        $now  = time();
        $data = $this->get($key);

        // Reset window if expired
        if ($data === null || $now >= $data['expires_at']) {
            $data = [
                'hits'       => 0,
                'expires_at' => $now + $windowSecs,
            ];
        }

        $data['hits']++;
        $this->put($key, $data);

        return $data['hits'] > $maxHits;
    }

    /**
     * How many seconds remain in the current window for the given key.
     */
    public function retryAfter(string $key): int
    {
        $data = $this->get($key);

        if ($data === null) {
            return 0;
        }

        return max(0, $data['expires_at'] - time());
    }

    /**
     * Reset hit counter for the given key.
     */
    public function reset(string $key): void
    {
        $path = $this->path($key);
        if (file_exists($path)) {
            unlink($path);
        }
    }

    // -------------------------------------------------------------------------
    // Overridable storage methods
    // -------------------------------------------------------------------------

    /**
     * @return array{hits: int, expires_at: int}|null
     */
    protected function get(string $key): ?array
    {
        $path = $this->path($key);

        if (!file_exists($path)) {
            return null;
        }

        $raw = file_get_contents($path);

        if ($raw === false) {
            return null;
        }

        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }

    /**
     * @param array{hits: int, expires_at: int} $data
     */
    protected function put(string $key, array $data): void
    {
        file_put_contents($this->path($key), json_encode($data), LOCK_EX);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function path(string $key): string
    {
        return $this->storageDir . '/' . md5($key) . '.json';
    }
}
