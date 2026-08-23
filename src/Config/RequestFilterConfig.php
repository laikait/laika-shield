<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class RequestFilterConfig
 *
 * General request filtering: HTTP method, URI patterns, User-Agent patterns,
 * required headers, forbidden header values and Content-Length bounds.
 *
 * @package Laika\Shield\Config
 */
final class RequestFilterConfig extends SectionConfig
{
    /** @var string[] HTTP methods that should be rejected outright. */
    private array $blockedMethods = ['TRACE', 'CONNECT'];

    /** @var string[] Regex patterns matched against REQUEST_URI. */
    private array $blockedUriPatterns = [];

    /** @var string[] Regex patterns matched against the User-Agent header. */
    private array $blockedUserAgents = [
        '/sqlmap/i',
        '/nikto/i',
        '/nessus/i',
        '/masscan/i',
        '/zgrab/i',
        '/python-requests\/[0-1]\./i', // old Python scanners
    ];

    /** @var string[] Request headers that MUST be present (lowercase names). */
    private array $requiredHeaders = [];

    /** @var array<string,string[]> Map of header name => forbidden regex patterns. */
    private array $blockedHeaderValues = [];

    private ?int $contentLengthMax = null;

    private ?int $contentLengthMin = null;

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function blockedMethods(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blockedMethods;
        }

        $this->blockedMethods = $value ?? [];
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function blockedUriPatterns(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blockedUriPatterns;
        }

        $this->blockedUriPatterns = $value ?? [];
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function blockedUserAgents(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blockedUserAgents;
        }

        $this->blockedUserAgents = $value ?? [];
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function requiredHeaders(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->requiredHeaders;
        }

        $this->requiredHeaders = $value ?? [];
        return $this;
    }

    /**
     * @param array<string,string[]>|null $value
     * @return static|array<string,string[]>
     */
    public function blockedHeaderValues(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blockedHeaderValues;
        }

        $this->blockedHeaderValues = $value ?? [];
        return $this;
    }

    /**
     * Null means "no limit" and is a legitimate value.
     *
     * @return static|int|null
     */
    public function contentLengthMax(?int $value = null): static|int|null
    {
        if (func_num_args() === 0) {
            return $this->contentLengthMax;
        }

        $this->contentLengthMax = $value;
        return $this;
    }

    /**
     * Null means "no limit" and is a legitimate value.
     *
     * @return static|int|null
     */
    public function contentLengthMin(?int $value = null): static|int|null
    {
        if (func_num_args() === 0) {
            return $this->contentLengthMin;
        }

        $this->contentLengthMin = $value;
        return $this;
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'blocked.methods'       => 'blockedMethods',
            'blocked.uri.patterns'  => 'blockedUriPatterns',
            'blocked.user.agents'   => 'blockedUserAgents',
            'headers.required'      => 'requiredHeaders',
            'blocked.header.values' => 'blockedHeaderValues',
            'content.length.max'    => 'contentLengthMax',
            'content.length.min'    => 'contentLengthMin',
        ];
    }
}
