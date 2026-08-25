<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\ShieldConfig;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\ShieldConfig
 */
class ConfigTest extends TestCase
{
    protected function setUp(): void
    {
        ShieldConfig::reset();
    }

    protected function tearDown(): void
    {
        ShieldConfig::reset();
    }

    /**
     * Both reads used an undefined $instance, silenced by ??, so the existing
     * value was always null and the array_merge branch was dead: every add()
     * overwrote what was there.
     */
    public function testTwoArgumentAddMergesInsteadOfOverwriting(): void
    {
        ShieldConfig::add('ip', ['blocklist' => ['1.1.1.1']]);
        ShieldConfig::add('ip', ['allowlist' => ['2.2.2.2']]);

        $ip = ShieldConfig::get('ip');

        $this->assertSame(['1.1.1.1'], $ip['blocklist']);
        $this->assertSame(['2.2.2.2'], $ip['allowlist']);
    }

    public function testThreeArgumentAddMergesArrayValues(): void
    {
        ShieldConfig::add('sql.injection', 'skip.keys', ['password']);
        ShieldConfig::add('sql.injection', 'skip.keys', ['token']);

        $this->assertSame(['password', 'token'], ShieldConfig::get('sql.injection')['skip.keys']);
    }

    public function testThreeArgumentAddReplacesScalarValues(): void
    {
        ShieldConfig::add('rate.limit', 'max.hits', 30);
        $this->assertSame(30, ShieldConfig::get('rate.limit')['max.hits']);

        ShieldConfig::add('rate.limit', 'max.hits', 10);
        $this->assertSame(10, ShieldConfig::get('rate.limit')['max.hits']);
    }

    public function testThreeArgumentAddLeavesSiblingKeysIntact(): void
    {
        ShieldConfig::add('rate.limit', 'max.hits', 30);

        $rateLimit = ShieldConfig::get('rate.limit');

        $this->assertSame(30, $rateLimit['max.hits']);
        $this->assertArrayHasKey('window', $rateLimit, 'Sibling keys must survive a sub-key update.');
        $this->assertSame(60, $rateLimit['window']);
    }

    public function testTopLevelScalarIsSet(): void
    {
        ShieldConfig::add('trust.proxy', true);
        $this->assertTrue(ShieldConfig::get('trust.proxy'));
    }

    public function testHasAndKeys(): void
    {
        $this->assertTrue(ShieldConfig::has('rate.limit'));
        $this->assertFalse(ShieldConfig::has('no.such.key'));
        $this->assertContains('xss', ShieldConfig::keys());
    }

    /**
     * The shipped defaults must not enable strict SQL matching — it blocks
     * ordinary prose.
     */
    public function testStrictSqlMatchingIsOffByDefault(): void
    {
        $this->assertFalse(ShieldConfig::get('sql.injection')['strict']);
    }

    public function testDefaultsIncludeTrustedProxiesKey(): void
    {
        $this->assertTrue(ShieldConfig::has('trusted.proxies'));
        $this->assertSame([], ShieldConfig::get('trusted.proxies'));
    }
}
