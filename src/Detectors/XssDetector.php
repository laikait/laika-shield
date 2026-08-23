<?php

declare(strict_types=1);

namespace Laika\Shield\Detectors;

use Laika\Shield\Contract\DetectorInterface;

/**
 * Class XssDetector
 *
 * Detects common Cross-Site Scripting (XSS) patterns in user-supplied input.
 *
 * Event-handler and tag patterns are anchored to markup context. An unanchored
 * /\bon\w+\s*=/ blocks "online=1", "once=true" and "ondemand=yes" — all ordinary
 * query parameters.
 *
 * @package Laika\Shield\Detectors
 */
final class XssDetector implements DetectorInterface
{
    private const PATTERNS = [
        // Script tags
        '/<\s*script\b/i',
        '/<\/\s*script\s*>/i',

        // Event handlers, but only inside a tag: "<tag ... onerror=" or an
        // attribute list continuing after a quote. Bare "online=1" is not markup.
        '/<[^>]*\son\w+\s*=/i',
        '/[\'"][^\'"]*\son\w+\s*=/i',

        // Script-bearing URL protocols
        '/\b(javascript|vbscript|livescript|mocha)\s*:/i',

        // data: URIs carrying markup or scripts
        '/\bdata\s*:\s*(text\/html|image\/svg\+xml|application\/(x-)?javascript)/i',

        // expression() — legacy CSS-based XSS
        '/\bexpression\s*\(/i',

        // eval and friends
        '/\b(eval|settimeout|setinterval|function)\s*\(\s*[\'"]/i',
        '/\bnew\s+function\s*\(/i',

        // Framing / embedding tags
        '/<\s*(iframe|embed|object|applet|meta|base)\b/i',

        // <svg> only when it carries an event handler or a script child — plain
        // inline SVG markup is legitimate content.
        '/<\s*svg\b[^>]*\son\w+\s*=/i',
        '/<\s*svg\b[\s\S]{0,200}?<\s*script\b/i',

        // Form action hijacking
        '/<\s*form\b[^>]*\baction\s*=/i',

        // srcdoc smuggles a whole document into an iframe
        '/\bsrcdoc\s*=/i',

        // CSS -moz-binding (Firefox XSS via XBL)
        '/-moz-binding/i',
    ];

    /**
     * Patterns applied to the ORIGINAL value, before decoding. Encoded angle
     * brackets only mean an attack while they are still encoded; after
     * urldecode() they are just "<" and the tag patterns above handle them.
     */
    private const RAW_PATTERNS = [
        // Double-encoded angle brackets: %253C -> %3C -> "<"
        '/%25(3C|3E)/i',
        // Encoded tag openers that survive a single decode pass
        '/(%3C|&lt;|&#0*60;|&#x0*3c;)\s*\/?\s*(script|iframe|img|svg|object|embed)\b/i',
    ];

    public function detect(string $value): bool
    {
        if ($value === '') {
            return false;
        }

        foreach (self::RAW_PATTERNS as $pattern) {
            if ($this->matches($pattern, $value)) {
                return true;
            }
        }

        $decoded = html_entity_decode(urldecode($value), ENT_QUOTES | ENT_HTML5, 'UTF-8');

        foreach (self::PATTERNS as $pattern) {
            if ($this->matches($pattern, $decoded)) {
                return true;
            }
        }

        return false;
    }

    public function name(): string
    {
        return 'XSS Detector';
    }

    /**
     * preg_match() returns false on PCRE failure (backtrack limit, bad UTF-8).
     * Treating that as "clean" would let a large crafted payload bypass the
     * scanner entirely, so a failure counts as a detection.
     */
    private function matches(string $pattern, string $subject): bool
    {
        $result = preg_match($pattern, $subject);

        return $result === false || $result === 1;
    }
}
