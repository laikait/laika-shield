<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\ShieldConfig;
use Laika\Shield\Config\CountryConfig;
use Laika\Shield\Config\IpConfig;
use Laika\Shield\Config\RateLimitConfig;
use Laika\Shield\Config\RequestFilterConfig;
use Laika\Shield\Config\SqlInjectionConfig;
use Laika\Shield\Config\XssConfig;
use Laika\Shield\Rules\RateLimitRule;
use Laika\Shield\Shield;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * Static section accessors: ShieldConfig::rateLimit()->maxHits(30)
 *
 * @covers \Laika\Shield\ShieldConfig
 */
class ConfigSectionAccessorTest extends TestCase
{
    protected function setUp(): void
    {
        ShieldConfig::reset();

        $_SERVER['REMOTE_ADDR']    = '203.0.113.5';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';
    }

    protected function tearDown(): void
    {
        ShieldConfig::reset();
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    }

    /**
     * @return array<string,array{0:string,1:class-string}>
     */
    public static function sections(): array
    {
        return [
            'ip'            => ['ip', IpConfig::class],
            'rateLimit'     => ['rateLimit', RateLimitConfig::class],
            'sqlInjection'  => ['sqlInjection', SqlInjectionConfig::class],
            'xss'           => ['xss', XssConfig::class],
            'requestFilter' => ['requestFilter', RequestFilterConfig::class],
            'country'       => ['country', CountryConfig::class],
        ];
    }

    /**
     * @dataProvider sections
     */
    public function testAccessorReturnsTheCorrectType(string $accessor, string $class): void
    {
        $this->assertInstanceOf($class, ShieldConfig::$accessor());
    }

    /**
     * The accessor must hand back the very same object the shared instance holds,
     * not a copy — otherwise mutations through it would go nowhere.
     *
     * @dataProvider sections
     */
    public function testAccessorReturnsTheSharedInstanceSection(string $accessor): void
    {
        $this->assertSame(ShieldConfig::instance()->{$accessor}, ShieldConfig::$accessor());
    }

    /**
     * @dataProvider sections
     */
    public function testAccessorFollowsReset(string $accessor): void
    {
        $before = ShieldConfig::$accessor();

        ShieldConfig::reset();

        $this->assertNotSame($before, ShieldConfig::$accessor(), 'A stale section must not survive reset().');
        $this->assertSame(ShieldConfig::instance()->{$accessor}, ShieldConfig::$accessor());
    }

    // -------------------------------------------------------------------------
    // Writing through the accessors
    // -------------------------------------------------------------------------

    public function testOptionsChainThroughTheAccessor(): void
    {
        ShieldConfig::rateLimit()->maxHits(30)->window(120);

        $this->assertSame(30, ShieldConfig::rateLimit()->maxHits());
        $this->assertSame(120, ShieldConfig::rateLimit()->window());
    }

    public function testRequestFilterRequiredHeaders(): void
    {
        ShieldConfig::requestFilter()->requiredHeaders(['x-api-key']);

        $this->assertSame(['x-api-key'], ShieldConfig::requestFilter()->requiredHeaders());

        // Sibling defaults must survive.
        $this->assertSame(['TRACE', 'CONNECT'], ShieldConfig::requestFilter()->blockedMethods());
    }

    public function testWritesAreVisibleThroughTheStaticFacade(): void
    {
        ShieldConfig::ip()->blocklist(['1.2.3.4']);

        $this->assertSame(['1.2.3.4'], ShieldConfig::get('ip')['blocklist']);
    }

    public function testFacadeWritesAreVisibleThroughTheAccessor(): void
    {
        ShieldConfig::add('rate.limit', 'max.hits', 7);

        $this->assertSame(7, ShieldConfig::rateLimit()->maxHits());
    }

    /**
     * The whole point: what you set here must be what boot() runs.
     */
    public function testAccessorWritesReachTheBuiltRules(): void
    {
        ShieldConfig::rateLimit()->maxHits(5);

        $rules = new ReflectionProperty(Shield::class, 'rules');
        $rules->setAccessible(true);

        $built = $rules->getValue(Shield::fromConfig(ShieldConfig::instance()));
        $found = array_values(array_filter($built, fn ($r) => $r instanceof RateLimitRule));

        $this->assertCount(1, $found);

        $maxHits = new ReflectionProperty(RateLimitRule::class, 'maxHits');
        $maxHits->setAccessible(true);

        $this->assertSame(5, $maxHits->getValue($found[0]));
    }

    // -------------------------------------------------------------------------
    // The documented trap
    // -------------------------------------------------------------------------

    /**
     * Static accessors ALWAYS resolve the shared instance. Holding a detached
     * config and reaching for ShieldConfig::rateLimit() configures the wrong object —
     * the same silent no-op that made a public `new ShieldConfig()` a trap.
     */
    public function testStaticAccessorsDoNotTouchADetachedConfig(): void
    {
        $detached = ShieldConfig::make();

        ShieldConfig::rateLimit()->maxHits(1);

        $this->assertSame(
            60,
            $detached->rateLimit->maxHits(),
            'A detached config must be unaffected by the static accessors.'
        );
        $this->assertSame(1, ShieldConfig::rateLimit()->maxHits());
    }

    public function testDetachedWritesDoNotLeakIntoTheSharedInstance(): void
    {
        $detached = ShieldConfig::make();
        $detached->rateLimit->maxHits(1);

        $this->assertSame(60, ShieldConfig::rateLimit()->maxHits());
    }
}
