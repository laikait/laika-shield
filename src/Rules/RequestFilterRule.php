<?php

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Support\RequestHelper;

/**
 * Class RequestFilterRule
 *
 * A versatile rule that can block requests based on:
 *  - HTTP method (e.g. block TRACE / CONNECT)
 *  - URI patterns (regex or plain prefixes)
 *  - Forbidden header values (e.g. block specific User-Agents)
 *  - Minimum / maximum Content-Length
 *  - Missing required headers
 *
 * @package Laika\Shield\Rules
 */
final class RequestFilterRule implements RuleInterface
{
    private string $blockMessage = '';

    /**
     * @param string[] $blockedMethods         HTTP methods to block (e.g. ['TRACE', 'CONNECT']).
     * @param string[] $blockedUriPatterns      Regex patterns matched against REQUEST_URI.
     * @param string[] $blockedUserAgentPatterns Regex patterns matched against User-Agent.
     * @param string[] $requiredHeaders         Header names (lowercase) that MUST be present.
     * @param array<string, string[]> $blockedHeaderValues
     *                                          Map of header name => list of forbidden value patterns.
     *                                          Example: ['content-type' => ['/text\/html/i']]
     * @param int|null $maxContentLength        Block if Content-Length exceeds this value (bytes).
     * @param int|null $minContentLength        Block if Content-Length is below this value (bytes).
     */
    public function __construct(
        private readonly array $blockedMethods = [],
        private readonly array $blockedUriPatterns = [],
        private readonly array $blockedUserAgentPatterns = [],
        private readonly array $requiredHeaders = [],
        private readonly array $blockedHeaderValues = [],
        private readonly ?int $maxContentLength = null,
        private readonly ?int $minContentLength = null,
    ) {}

    public function passes(): bool
    {
        // --- Method check ---
        $method = RequestHelper::method();
        if (!empty($this->blockedMethods) && in_array($method, $this->blockedMethods, true)) {
            $this->blockMessage = "HTTP method \"{$method}\" is not allowed.";
            return false;
        }

        // --- URI pattern check ---
        $uri = RequestHelper::uri();
        foreach ($this->blockedUriPatterns as $pattern) {
            if (preg_match($pattern, $uri)) {
                $this->blockMessage = "Request URI is blocked by filter pattern: {$pattern}.";
                return false;
            }
        }

        // --- Headers ---
        $headers = RequestHelper::headers();

        // User-Agent check
        $userAgent = $headers['user-agent'] ?? '';
        foreach ($this->blockedUserAgentPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                $this->blockMessage = "User-Agent is blocked by filter pattern: {$pattern}.";
                return false;
            }
        }

        // Required headers check
        foreach ($this->requiredHeaders as $required) {
            if (!isset($headers[strtolower($required)])) {
                $this->blockMessage = "Required header \"{$required}\" is missing.";
                return false;
            }
        }

        // Blocked header value check
        foreach ($this->blockedHeaderValues as $headerName => $patterns) {
            $headerValue = $headers[strtolower($headerName)] ?? '';
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $headerValue)) {
                    $this->blockMessage = "Header \"{$headerName}\" contains a blocked value.";
                    return false;
                }
            }
        }

        // --- Content-Length checks ---
        $contentLength = isset($headers['content-length'])
            ? (int) $headers['content-length']
            : null;

        if ($this->maxContentLength !== null && $contentLength !== null) {
            if ($contentLength > $this->maxContentLength) {
                $this->blockMessage = "Request body is too large ({$contentLength} bytes, max {$this->maxContentLength}).";
                return false;
            }
        }

        if ($this->minContentLength !== null && $contentLength !== null) {
            if ($contentLength < $this->minContentLength) {
                $this->blockMessage = "Request body is too small ({$contentLength} bytes, min {$this->minContentLength}).";
                return false;
            }
        }

        return true;
    }

    public function message(): string
    {
        return $this->blockMessage;
    }
}
