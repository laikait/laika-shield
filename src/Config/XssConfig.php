<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class XssConfig
 *
 * skipKeys:    Input parameter names to exempt (e.g. rich-text editors).
 * scanBody:    Whether to also scan the raw request body.
 * scanHeaders: Whether to also inspect request headers.
 *
 * @package Laika\Shield\Config
 */
final class XssConfig extends SectionConfig
{
    /** @var string[] */
    private array $skipKeys = [];

    private bool $scanBody = true;

    private bool $scanHeaders = false;

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function skipKeys(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->skipKeys;
        }

        $this->skipKeys = $value ?? [];
        return $this;
    }

    /**
     * @return static|bool
     */
    public function scanBody(?bool $value = null): static|bool
    {
        if (func_num_args() === 0) {
            return $this->scanBody;
        }

        $this->scanBody = (bool) $value;
        return $this;
    }

    /**
     * @return static|bool
     */
    public function scanHeaders(?bool $value = null): static|bool
    {
        if (func_num_args() === 0) {
            return $this->scanHeaders;
        }

        $this->scanHeaders = (bool) $value;
        return $this;
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'skip.keys'    => 'skipKeys',
            'scan.body'    => 'scanBody',
            'scan.headers' => 'scanHeaders',
        ];
    }
}
