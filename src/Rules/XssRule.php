<?php

declare(strict_types=1);

namespace Laika\Shield\Rules;

use Laika\Shield\Interfaces\RuleInterface;
use Laika\Shield\Detectors\XssDetector;
use Laika\Shield\Support\RequestHelper;

/**
 * Class XssRule
 *
 * Scans query parameters, POST body, headers, and raw input for XSS patterns.
 *
 * @package Laika\Shield\Rules
 */
final class XssRule implements RuleInterface
{
    private string $blockMessage = '';

    /**
     * @param string[] $skipKeys      Input keys to skip (e.g. ['content', 'html_body']).
     * @param bool     $scanHeaders   Whether to also scan request headers.
     * @param bool     $scanBody      Whether to also scan the raw request body.
     */
    public function __construct(
        private readonly array $skipKeys = [],
        private readonly bool $scanHeaders = false,
        private readonly bool $scanBody = true,
    ) {}

    public function passes(): bool
    {
        $detector = new XssDetector();

        $inputs = $this->scanBody
            ? RequestHelper::allInput()
            : array_merge(RequestHelper::queryParams(), RequestHelper::bodyParams());

        if ($this->scanHeaders) {
            $inputs = array_merge($inputs, RequestHelper::headers());
        }

        foreach ($inputs as $key => $value) {
            if (in_array($key, $this->skipKeys, true)) {
                continue;
            }

            if ($detector->detect($value)) {
                $this->blockMessage = "XSS attack detected in input key: \"{$key}\".";
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
