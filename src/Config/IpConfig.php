<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class IpConfig
 *
 * blocklist: Any request from these IPs or CIDR ranges is denied.
 * allowlist: When non-empty, ONLY these IPs/ranges are permitted.
 *            (The blocklist is still applied after the allowlist check.)
 *
 * @package Laika\Shield\Config
 */
final class IpConfig extends SectionConfig
{
    /** @var string[] */
    private array $blocklist = [];

    /** @var string[] */
    private array $allowlist = [];

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function blocklist(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->blocklist;
        }

        $this->blocklist = $value ?? [];
        return $this;
    }

    /**
     * @param string[]|null $value
     * @return static|string[]
     */
    public function allowlist(?array $value = null): static|array
    {
        if (func_num_args() === 0) {
            return $this->allowlist;
        }

        $this->allowlist = $value ?? [];
        return $this;
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'blocklist' => 'blocklist',
            'allowlist' => 'allowlist',
        ];
    }
}
