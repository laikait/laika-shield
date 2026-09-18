<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Relay;

use Laika\Shield\Shield;
use Laika\Shield\ShieldConfig;
use Laika\Relay\RelayProvider;
use Laika\Relay\Relay;

class ShieldRelay extends RelayProvider
{
    public function register(): void
    {
        // laika-framework requires this package, so this package can never
        // require the framework back without creating a Composer cycle. The
        // relay contract is therefore only assumed present, never guaranteed.
        if (!class_exists(Relay::class)) {
            return;
        }

        // A factory, not the class name: the constructor is protected, so the
        // registry could never build it, and the relay must hand back the same
        // shared instance Shield::boot() reads.
        $this->registry->singleton('shield.config', fn () => ShieldConfig::instance());
        $this->registry->singleton('shield', Shield::class);
    }
}
