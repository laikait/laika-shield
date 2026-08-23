<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class SqlInjectionConfig
 *
 * skipKeys: Input parameter names to exempt from scanning
 *           (e.g. fields where raw SQL-like syntax is expected).
 * scanBody: Whether to also scan the raw request body (JSON APIs, etc.).
 * strict:   Also block bare SQL keywords ("select ... from") that carry no
 *           injection syntax. OFF by default — it false-positives on ordinary
 *           prose, so only enable it for fields that never hold free text.
 *
 * @package Laika\Shield\Config
 */
final class SqlInjectionConfig extends SectionConfig
{
    /** @var string[] */
    private array $skipKeys = [];

    private bool $scanBody = true;

    private bool $strict = false;

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
    public function strict(?bool $value = null): static|bool
    {
        if (func_num_args() === 0) {
            return $this->strict;
        }

        $this->strict = (bool) $value;
        return $this;
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'skip.keys' => 'skipKeys',
            'scan.body' => 'scanBody',
            'strict'    => 'strict',
        ];
    }
}
