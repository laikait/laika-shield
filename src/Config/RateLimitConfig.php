<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Config;

/**
 * Class RateLimitConfig
 *
 * maxHits:    Maximum requests allowed per client IP within the window.
 * window:     Window size in seconds.
 * storageDir: Directory for rate-limit state files.
 *             Defaults to sys_get_temp_dir()/laika_shield_rl when null.
 *
 * @package Laika\Shield\Config
 */
final class RateLimitConfig extends SectionConfig
{
    private int $maxHits = 60;

    private int $window = 60;

    private ?string $storageDir = null;

    /**
     * @return static|int
     */
    public function maxHits(?int $value = null): static|int
    {
        if (func_num_args() === 0) {
            return $this->maxHits;
        }

        $this->maxHits = (int) $value;
        return $this;
    }

    /**
     * @return static|int
     */
    public function window(?int $value = null): static|int
    {
        if (func_num_args() === 0) {
            return $this->window;
        }

        $this->window = (int) $value;
        return $this;
    }

    /**
     * Null is a legitimate value here — it means "use the system temp directory".
     *
     * @return static|string|null
     */
    public function storageDir(?string $value = null): static|string|null
    {
        if (func_num_args() === 0) {
            return $this->storageDir;
        }

        $this->storageDir = $value;
        return $this;
    }

    /**
     * @inheritDoc
     */
    protected function keyMap(): array
    {
        return [
            'max.hits'    => 'maxHits',
            'window'      => 'window',
            'storage.dir' => 'storageDir',
        ];
    }
}
