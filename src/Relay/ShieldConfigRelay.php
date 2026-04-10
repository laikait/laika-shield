<?php
/**
 * Name: Laika Shield
 * Provider: Laika IT
 * Email: strblackhawk@gmail.com
 */

declare(strict_types=1);

namespace Laika\Shield\Relay;

use Laika\Core\Relay\Relay;

class ShieldConfigRelay extends Relay
{
    protected static function getRelayAccessor(): string
    {
        return 'shield.config';
    } 
}