<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Relay;

use Laika\Shield\Shield;
use Laika\Shield\Config;
use Laika\Relay\RelayProvider;

class ShieldRelay extends RelayProvider
{
    public function register(): void
    {
        $this->registry->singleton('shield.config', Config::class);
        $this->registry->singleton('shield', Shield::class);
    } 
}
