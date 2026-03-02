<?php

declare(strict_types=1);

/**
 * Laika Shield — Firewall Configuration
 *
 * Copy this file to your project's config directory and adjust as needed.
 * Pass this array to Shield::boot() or ShieldMiddleware.
 *
 * @package Laika\Shield
 */

return [

    // -------------------------------------------------------------------------
    // Proxy Trust
    // -------------------------------------------------------------------------
    // Set to true if your application sits behind a reverse proxy (Nginx,
    // Cloudflare, AWS ALB, etc.) so that Shield reads the real client IP
    // from X-Forwarded-For / CF-Connecting-IP headers.
    //
    'trust_proxy' => false,

    // -------------------------------------------------------------------------
    // IP Blocking & Allowlisting
    // -------------------------------------------------------------------------
    // blocklist: Any request from these IPs or CIDR ranges will be denied.
    // allowlist: When non-empty, ONLY these IPs/ranges are permitted.
    //            (blocklist is still applied after the allowlist check.)
    //
    'ip' => [
        'blocklist' => [
            // '1.2.3.4',
            // '192.168.100.0/24',
        ],
        'allowlist' => [
            // '203.0.113.0/24',
        ],
    ],

    // -------------------------------------------------------------------------
    // IP Version Filtering
    // -------------------------------------------------------------------------
    // Set to 4 to allow only IPv4 connections, 6 for IPv6 only.
    // Set to null (or remove the key) to allow both.
    //
    'ip_version' => null,

    // -------------------------------------------------------------------------
    // Rate Limiting
    // -------------------------------------------------------------------------
    // max_hits:    Maximum requests allowed per client IP within the window.
    // window:      Window size in seconds.
    // storage_dir: Directory for rate-limit state files.
    //              Defaults to sys_get_temp_dir()/laika_shield_rl
    //
    'rate_limit' => [
        'max_hits'    => 60,
        'window'      => 60,
        'storage_dir' => null,
    ],

    // -------------------------------------------------------------------------
    // SQL Injection Detection
    // -------------------------------------------------------------------------
    // skip_keys: Input parameter names to exempt from scanning
    //            (e.g. fields where raw SQL-like syntax is expected).
    // scan_body: Whether to also scan the raw request body (JSON APIs, etc.).
    //
    'sql_injection' => [
        'skip_keys' => [],
        'scan_body' => true,
    ],

    // -------------------------------------------------------------------------
    // XSS Detection
    // -------------------------------------------------------------------------
    // skip_keys:    Input parameter names to exempt (e.g. rich-text editors).
    // scan_headers: Whether to also inspect request headers.
    // scan_body:    Whether to also scan the raw request body.
    //
    'xss' => [
        'skip_keys'    => [],
        'scan_headers' => false,
        'scan_body'    => true,
    ],

    // -------------------------------------------------------------------------
    // Request Filtering
    // -------------------------------------------------------------------------
    'request_filter' => [

        // HTTP methods that should be rejected outright.
        'blocked_methods' => [
            'TRACE',
            'CONNECT',
        ],

        // Regex patterns matched against REQUEST_URI.
        'blocked_uri_patterns' => [
            // '/\/\.env$/i',
            // '/\/wp-admin/i',
            // '/\/phpmyadmin/i',
        ],

        // Regex patterns matched against the User-Agent header.
        'blocked_user_agents' => [
            '/sqlmap/i',
            '/nikto/i',
            '/nessus/i',
            '/masscan/i',
            '/zgrab/i',
            '/python-requests\/[0-1]\./i', // old Python scanners
        ],

        // Request headers that MUST be present (lowercase names).
        'required_headers' => [
            // 'x-api-key',
        ],

        // Map of header name => list of forbidden regex patterns.
        'blocked_header_values' => [
            // 'content-type' => ['/multipart\/form-data/i'],
        ],

        // Block requests whose Content-Length exceeds this value (bytes).
        // null = no limit.
        'max_content_length' => null,

        // Block requests whose Content-Length is below this value.
        // null = no limit.
        'min_content_length' => null,
    ],

];
