<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Support;

/**
 * Class IpHelper
 *
 * Utility methods for IP address detection, validation, and version detection.
 *
 * @package Laika\Shield\Support
 */
final class IpHelper
{
    // -------------------------------------------------------------------------
    // IP Version Detection
    // -------------------------------------------------------------------------

    /**
     * Detect whether an IP is v4 or v6.
     *
     * @return 4|6|null  Returns 4 for IPv4, 6 for IPv6, null if invalid.
     */
    public static function version(string $ip): int|null
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return 4;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return 6;
        }

        return null;
    }

    /**
     * Check whether the IP is a valid IPv4 address.
     */
    public static function isV4(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    /**
     * Check whether the IP is a valid IPv6 address.
     */
    public static function isV6(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
    }

    /**
     * Check whether the IP is valid (either v4 or v6).
     */
    public static function isValid(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP);
    }

    // -------------------------------------------------------------------------
    // CIDR / Range Matching
    // -------------------------------------------------------------------------

    /**
     * Check whether an IP falls inside a CIDR range (e.g. 192.168.0.0/24).
     * Supports both IPv4 and IPv6 CIDR notation.
     */
    public static function inCidr(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $prefix] = explode('/', $cidr, 2);

        // An out-of-range prefix used to reach a negative bit shift, which is a
        // fatal ArithmeticError in PHP 8 — one typo in a blocklist took down every
        // request. Reject the range instead.
        if ($prefix === '' || !ctype_digit($prefix)) {
            return false;
        }

        $prefix = (int) $prefix;

        if (self::isV4($ip) && self::isV4($subnet)) {
            return $prefix <= 32 && self::inCidrV4($ip, $subnet, $prefix);
        }

        if (self::isV6($ip) && self::isV6($subnet)) {
            return $prefix <= 128 && self::inCidrV6($ip, $subnet, $prefix);
        }

        return false;
    }

    /**
     * Check whether the IP is inside any of the given CIDR ranges.
     *
     * @param string[] $cidrs
     */
    public static function inAnyCidr(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::inCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Special-purpose IP checks
    // -------------------------------------------------------------------------

    /**
     * Returns true if the IP is a loopback address (127.x.x.x or ::1).
     */
    public static function isLoopback(string $ip): bool
    {
        return self::inCidr($ip, '127.0.0.0/8') || $ip === '::1';
    }

    /**
     * Returns true if the IP is a private/RFC-1918 or private IPv6 address.
     */
    public static function isPrivate(string $ip): bool
    {
        if (self::isV4($ip)) {
            return self::inAnyCidr($ip, [
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '127.0.0.0/8',
            ]);
        }

        if (self::isV6($ip)) {
            // fc00::/7 — Unique Local Addresses
            return self::inCidr($ip, 'fc00::/7') || $ip === '::1';
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Client IP resolution
    // -------------------------------------------------------------------------

    /**
     * Resolve the real client IP.
     *
     * Forwarded headers are attacker-controlled unless a trusted proxy put them
     * there, so they are only consulted when $trustProxy is on, and single-value
     * headers (CF-Connecting-IP, X-Real-IP) are only believed when the immediate
     * peer is inside $trustedProxies.
     *
     * X-Forwarded-For is appended left-to-right, so the LEFTMOST entry is the one
     * the client fully controls and the rightmost is the one our own proxy wrote.
     * We therefore walk from the right, discarding hops we trust, and take the
     * first address we did not put there ourselves.
     *
     * @param bool     $trustProxy      Whether to consult proxy headers at all.
     * @param string[] $trustedProxies  IPs/CIDRs of your own proxies. Strongly
     *                                  recommended: without it the single-value
     *                                  headers are ignored entirely.
     * @return string
     */
    public static function resolve(bool $trustProxy = false, array $trustedProxies = []): string
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        if (!$trustProxy) {
            return $remote;
        }

        $peerIsTrusted = !empty($trustedProxies) && self::inAnyCidr($remote, $trustedProxies);

        // Headers a proxy sets wholesale. A direct client can send these too, so
        // they are only trustworthy when we know the peer is our proxy.
        if ($peerIsTrusted) {
            foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $header) {
                $value = trim((string) ($_SERVER[$header] ?? ''));

                if ($value !== '' && self::isValid($value)) {
                    return $value;
                }
            }
        }

        $forwarded = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');

        if ($forwarded !== '') {
            $hops = array_values(array_filter(array_map('trim', explode(',', $forwarded))));

            // Right-to-left: skip our own proxies, stop at the first hop we did not add.
            for ($i = count($hops) - 1; $i >= 0; $i--) {
                $hop = self::normalise($hops[$i]);

                if (!self::isValid($hop)) {
                    break;
                }

                if (!empty($trustedProxies) && self::inAnyCidr($hop, $trustedProxies)) {
                    continue;
                }

                return $hop;
            }
        }

        return $remote;
    }

    /**
     * Strip a port and IPv6 brackets from a forwarded-header hop.
     */
    private static function normalise(string $hop): string
    {
        if (str_starts_with($hop, '[')) {
            $end = strpos($hop, ']');
            return $end !== false ? substr($hop, 1, $end - 1) : $hop;
        }

        // "1.2.3.4:5678" — only strip when it is unambiguously a v4 host:port pair.
        if (substr_count($hop, ':') === 1) {
            return explode(':', $hop, 2)[0];
        }

        return $hop;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static function inCidrV4(string $ip, string $subnet, int $prefix): bool
    {
        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        $mask       = $prefix === 0 ? 0 : (~0 << (32 - $prefix));

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private static function inCidrV6(string $ip, string $subnet, int $prefix): bool
    {
        $ipBin     = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $bits   = 128;
        $ipArr  = unpack('C*', $ipBin);
        $subArr = unpack('C*', $subnetBin);

        $bytesFull = (int) ($prefix / 8);
        $bitsLeft  = $prefix % 8;

        // Compare full bytes
        for ($i = 1; $i <= $bytesFull; $i++) {
            if ($ipArr[$i] !== $subArr[$i]) {
                return false;
            }
        }

        // Compare remaining partial byte
        if ($bitsLeft > 0 && $bytesFull < 16) {
            $mask = 0xFF & (0xFF << (8 - $bitsLeft));
            if (($ipArr[$bytesFull + 1] & $mask) !== ($subArr[$bytesFull + 1] & $mask)) {
                return false;
            }
        }

        return true;
    }
}
