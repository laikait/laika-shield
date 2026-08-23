<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Config;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Laika\Shield\Config
 */
class ConfigTest extends TestCase
{
    protected function setUp(): void
    {
        Config::reset();
    }

    protected function tearDown(): void
    {
        Config::reset();
    }

    /**
     * Both reads used an undefined $instance, silenced by ??, so the existing
     * value was always null and the array_merge branch was dead: every add()
     * overwrote what was there.
     */
    public function testTwoArgumentAddMergesInsteadOfOverwriting(): void
    {
        Config::add('ip', ['blocklist' => ['1.1.1.1']]);
        Config::add('ip', ['allowlist' => ['2.2.2.2']]);

        $ip = Config::get('ip');

        $this->assertSame(['1.1.1.1'], $ip['blocklist']);
        $this->assertSame(['2.2.2.2'], $ip['allowlist']);
    }

    public function testThreeArgumentAddMergesArrayValues(): void
    {
        Config::add('sql.injection', 'skip.keys', ['password']);
        Config::add('sql.injection', 'skip.keys', ['token']);

        $this->assertSame(['password', 'token'], Config::get('sql.injection')['skip.keys']);
    }

    public function testThreeArgumentAddReplacesScalarValues(): void
    {
        Config::add('rate.limit', 'max.hits', 30);
        $this->assertSame(30, Config::get('rate.limit')['max.hits']);

        Config::add('rate.limit', 'max.hits', 10);
        $this->assertSame(10, Config::get('rate.limit')['max.hits']);
    }

    public function testThreeArgumentAddLeavesSiblingKeysIntact(): void
    {
        Config::add('rate.limit', 'max.hits', 30);

        $rateLimit = Config::get('rate.limit');

        $this->assertSame(30, $rateLimit['max.hits']);
        $this->assertArrayHasKey('window', $rateLimit, 'Sibling keys must survive a sub-key update.');
        $this->assertSame(60, $rateLimit['window']);
    }

    public function testTopLevelScalarIsSet(): void
    {
        Config::add('trust.proxy', true);
        $this->assertTrue(Config::get('trust.proxy'));
    }

    public function testHasAndKeys(): void
    {
        $this->assertTrue(Config::has('rate.limit'));
        $this->assertFalse(Config::has('no.such.key'));
        $this->assertContains('xss', Config::keys());
    }

    /**
     * The shipped defaults must not enable strict SQL matching — it blocks
     * ordinary prose.
     */
    public function testStrictSqlMatchingIsOffByDefault(): void
    {
        $this->assertFalse(Config::get('sql.injection')['strict']);
    }

    public function testDefaultsIncludeTrustedProxiesKey(): void
    {
        $this->assertTrue(Config::has('trusted.proxies'));
        $this->assertSame([], Config::get('trusted.proxies'));
    }
}
