<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use Laika\Shield\Interfaces\DetectorInterface;

/**
 * Class XssDetector
 *
 * Detects common Cross-Site Scripting (XSS) patterns in user-supplied input.
 *
 * @package Laika\Shield\Detectors
 */
final class XssDetector implements DetectorInterface
{
    private const PATTERNS = [
        // Script tags
        '/<\s*script[^>]*>/i',
        '/<\/\s*script\s*>/i',
        // Event handlers (onclick, onerror, onload, …)
        '/\bon\w+\s*=/i',
        // javascript: and vbscript: protocol
        '/\b(javascript|vbscript|livescript|mocha)\s*:/i',
        // data: URIs with potential execution context
        '/\bdata\s*:\s*\w+\/\w+\s*;/i',
        // expression() — CSS-based XSS
        '/\bexpression\s*\(/i',
        // eval / setTimeout / setInterval with strings
        '/\b(eval|settimeout|setinterval|new\s+function)\s*\(/i',
        // <iframe>, <embed>, <object>, <form>
        '/<\s*(iframe|embed|object|form)[^>]*>/i',
        // <img> with src tricks
        '/<\s*img[^>]+src\s*=\s*["\']?\s*javascript/i',
        // SVG with event handler
        '/<\s*svg[^>]*>/i',
        // URL-encoded < >
        '/(%3C|%3E|%22|%27)/i',
        // HTML entity encoded script
        '/&#(?:x[0-9a-fA-F]+|[0-9]+);/i',
        // CSS -moz-binding (Firefox XSS via XBL)
        '/-moz-binding/i',
    ];

    public function detect(string $value): bool
    {
        $decoded = html_entity_decode(urldecode($value), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        foreach (self::PATTERNS as $pattern) {
            if (preg_match($pattern, $decoded)) {
                return true;
            }
        }

        return false;
    }

    public function name(): string
    {
        return 'XSS Detector';
    }
}
