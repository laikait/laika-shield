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
 * The whole read-modify-write is held under a single exclusive lock. Locking only
 * the write is not enough: concurrent requests read the same count and overwrite
 * each other, undercounting during exactly the burst the limit exists to stop.
 *
 * For a high-traffic multi-server deployment, extend this class and override
 * {@see tooMany()} with an atomic backend (Redis INCR, etc.) — a shared filesystem
 * is not a good lock substrate.
 *
 * @package Laika\Shield\Support
 */
class RateLimiter
{
    private string $storageDir;

    public function __construct(?string $storageDir = null)
    {
        $base = $storageDir ?? sys_get_temp_dir();

        $this->storageDir = rtrim(str_replace(DIRECTORY_SEPARATOR, '/', $base), '/') . '/laika_shield_rl';

        if (!is_dir($this->storageDir)) {
            // Concurrent requests race here; recursive mkdir failing because
            // someone else won is not an error.
            @mkdir($this->storageDir, 0700, true);
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
        $now    = time();
        $handle = @fopen($this->path($key), 'c+');

        if ($handle === false) {
            // Storage unavailable. Fail open rather than locking every client out
            // of the application because the temp directory is unwritable.
            return false;
        }

        try {
            if (!flock($handle, LOCK_EX)) {
                return false;
            }

            $data = $this->readLocked($handle);

            // Reset the window if it expired or the file was empty/corrupt.
            if ($data === null || $now >= $data['expires_at']) {
                $data = [
                    'hits'       => 0,
                    'expires_at' => $now + $windowSecs,
                ];
            }

            $data['hits']++;

            $this->writeLocked($handle, $data);

            return $data['hits'] > $maxHits;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
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
            @unlink($path);
        }
    }

    // -------------------------------------------------------------------------
    // Overridable storage methods
    // -------------------------------------------------------------------------

    /**
     * Read the current window without taking a lock. Safe for reporting
     * (retryAfter) but never for the increment path.
     *
     * @return array{hits: int, expires_at: int}|null
     */
    protected function get(string $key): ?array
    {
        $path = $this->path($key);

        if (!file_exists($path)) {
            return null;
        }

        $raw = @file_get_contents($path);

        return $raw === false ? null : $this->decode($raw);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * @param resource $handle
     * @return array{hits: int, expires_at: int}|null
     */
    private function readLocked($handle): ?array
    {
        rewind($handle);

        $raw  = '';
        $size = (int) (fstat($handle)['size'] ?? 0);

        if ($size > 0) {
            $raw = (string) fread($handle, $size);
        }

        return $this->decode($raw);
    }

    /**
     * @param resource $handle
     * @param array{hits: int, expires_at: int} $data
     */
    private function writeLocked($handle, array $data): void
    {
        $encoded = (string) json_encode($data);

        rewind($handle);
        ftruncate($handle, 0);
        fwrite($handle, $encoded);
        fflush($handle);
    }

    /**
     * @return array{hits: int, expires_at: int}|null
     */
    private function decode(string $raw): ?array
    {
        if ($raw === '') {
            return null;
        }

        $data = json_decode($raw, true);

        if (!is_array($data) || !isset($data['hits'], $data['expires_at'])) {
            return null;
        }

        return [
            'hits'       => (int) $data['hits'],
            'expires_at' => (int) $data['expires_at'],
        ];
    }

    private function path(string $key): string
    {
        return $this->storageDir . '/' . md5($key) . '.json';
    }
}
