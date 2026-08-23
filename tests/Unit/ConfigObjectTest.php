<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Config;
use Laika\Shield\Config\CountryConfig;
use Laika\Shield\Config\IpConfig;
use Laika\Shield\Config\RateLimitConfig;
use Laika\Shield\Config\RequestFilterConfig;
use Laika\Shield\Config\SqlInjectionConfig;
use Laika\Shield\Config\XssConfig;
use PHPUnit\Framework\TestCase;

/**
 * The object configuration API.
 *
 * @covers \Laika\Shield\Config
 * @covers \Laika\Shield\Config\SectionConfig
 */
class ConfigObjectTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Singleton contract
    // -------------------------------------------------------------------------

    /**
     * Config advertises singleton semantics (instance/reset), so the constructor
     * must not be public. A public one let callers build a detached config that
     * Shield::boot() could never see, which silently did nothing.
     */
    public function testConstructorIsNotPublic(): void
    {
        $constructor = (new \ReflectionClass(Config::class))->getConstructor();

        $this->assertNotNull($constructor);
        $this->assertFalse($constructor->isPublic(), 'Config::__construct() must not be public.');
    }

    public function testInstanceReturnsTheSameObjectEveryTime(): void
    {
        Config::reset();

        $this->assertSame(Config::instance(), Config::instance());

        Config::reset();
    }

    /**
     * make() is the detached escape hatch — explicitly NOT the shared instance.
     */
    public function testMakeReturnsADetachedInstance(): void
    {
        Config::reset();

        $detached = Config::make();

        $this->assertNotSame($detached, Config::instance());

        $detached->rateLimit->maxHits(1);
        $this->assertSame(60, Config::instance()->rateLimit->maxHits());

        Config::reset();
    }

    // -------------------------------------------------------------------------
    // Defaults live on the objects — there is no config file
    // -------------------------------------------------------------------------

    public function testNewConfigIsAlreadyComplete(): void
    {
        $config = Config::make();

        $this->assertFalse($config->trustProxy());
        $this->assertSame([], $config->trustedProxies());
        $this->assertNull($config->ipVersion());

        $this->assertInstanceOf(IpConfig::class, $config->ip);
        $this->assertInstanceOf(RateLimitConfig::class, $config->rateLimit);
        $this->assertInstanceOf(SqlInjectionConfig::class, $config->sqlInjection);
        $this->assertInstanceOf(XssConfig::class, $config->xss);
        $this->assertInstanceOf(RequestFilterConfig::class, $config->requestFilter);
        $this->assertInstanceOf(CountryConfig::class, $config->country);
    }

    public function testSectionDefaults(): void
    {
        $config = Config::make();

        $this->assertSame([], $config->ip->blocklist());
        $this->assertSame(60, $config->rateLimit->maxHits());
        $this->assertSame(60, $config->rateLimit->window());
        $this->assertNull($config->rateLimit->storageDir());
        $this->assertTrue($config->sqlInjection->scanBody());
        $this->assertTrue($config->xss->scanBody());
        $this->assertFalse($config->xss->scanHeaders());
        $this->assertSame(['TRACE', 'CONNECT'], $config->requestFilter->blockedMethods());
        $this->assertContains('/sqlmap/i', $config->requestFilter->blockedUserAgents());
        $this->assertSame('', $config->country->db());
    }

    /**
     * Strict SQL matching blocks ordinary prose, so it must stay off by default.
     */
    public function testStrictSqlMatchingIsOffByDefault(): void
    {
        $this->assertFalse((Config::make())->sqlInjection->strict());
    }

    // -------------------------------------------------------------------------
    // Fluent accessors
    // -------------------------------------------------------------------------

    public function testAccessorsReadAndWrite(): void
    {
        $config = Config::make();

        $this->assertSame($config, $config->trustProxy(true));
        $this->assertTrue($config->trustProxy());
    }

    public function testAccessorsChain(): void
    {
        $config = Config::make();

        $config->trustProxy(true)->trustedProxies(['10.0.0.0/8'])->ipVersion(4);

        $this->assertTrue($config->trustProxy());
        $this->assertSame(['10.0.0.0/8'], $config->trustedProxies());
        $this->assertSame(4, $config->ipVersion());
    }

    public function testSectionAccessorsChain(): void
    {
        $config = Config::make();

        $config->rateLimit->maxHits(30)->window(120);

        $this->assertSame(30, $config->rateLimit->maxHits());
        $this->assertSame(120, $config->rateLimit->window());
    }

    /**
     * Reads and writes are told apart with func_num_args(), not a null default.
     * A null-sentinel would make these options impossible to clear — the exact
     * bug that made the old Config::add() unable to write a null.
     */
    public function testNullableOptionsCanBeClearedBackToNull(): void
    {
        $config = Config::make();

        $config->rateLimit->storageDir('/tmp/x');
        $this->assertSame('/tmp/x', $config->rateLimit->storageDir());

        $config->rateLimit->storageDir(null);
        $this->assertNull($config->rateLimit->storageDir(), 'storageDir must be clearable.');

        $config->requestFilter->contentLengthMax(2048);
        $this->assertSame(2048, $config->requestFilter->contentLengthMax());

        $config->requestFilter->contentLengthMax(null);
        $this->assertNull($config->requestFilter->contentLengthMax());

        $config->ipVersion(4);
        $config->ipVersion(null);
        $this->assertNull($config->ipVersion());
    }

    // -------------------------------------------------------------------------
    // Array hydration — this is the merge
    // -------------------------------------------------------------------------

    /**
     * The regression that prompted the rewrite. A shallow array_merge would have
     * collapsed request.filter to just the supplied key, silently deleting the
     * method blocks and the scanner User-Agent patterns.
     */
    public function testPartialSectionKeepsItsOtherDefaults(): void
    {
        $config = Config::fromArray([
            'request.filter' => ['content.length.max' => 2048],
        ]);

        $this->assertSame(2048, $config->requestFilter->contentLengthMax());
        $this->assertSame(
            ['TRACE', 'CONNECT'],
            $config->requestFilter->blockedMethods(),
            'Supplying one option must not wipe the rest of the section.'
        );
        $this->assertContains('/sqlmap/i', $config->requestFilter->blockedUserAgents());
    }

    public function testPartialConfigKeepsOtherSections(): void
    {
        $config = Config::fromArray(['ip' => ['blocklist' => ['1.2.3.4']]]);

        $this->assertSame(['1.2.3.4'], $config->ip->blocklist());
        $this->assertSame(60, $config->rateLimit->maxHits());
        $this->assertTrue($config->xss->scanBody());
    }

    /**
     * Lists must be replaced wholesale, never concatenated onto the default —
     * the array_merge_recursive trap.
     */
    public function testListsAreReplacedNotConcatenated(): void
    {
        $config = Config::fromArray(['request.filter' => ['blocked.methods' => ['PATCH']]]);

        $this->assertSame(['PATCH'], $config->requestFilter->blockedMethods());
    }

    /**
     * array_merge_recursive turns trust.proxy from false into [false, true],
     * which casts to true and silently enables proxy trust. Hydration must not.
     */
    public function testScalarStaysScalar(): void
    {
        $config = Config::fromArray(['trust.proxy' => true]);

        $this->assertTrue($config->trustProxy());
        $this->assertIsBool($config->trustProxy());
    }

    public function testUnknownKeysAreIgnored(): void
    {
        $config = Config::fromArray(['no.such.key' => 'x', 'ip' => ['blocklist' => ['1.2.3.4']]]);

        $this->assertSame(['1.2.3.4'], $config->ip->blocklist());
        $this->assertArrayNotHasKey('no.such.key', $config->toArray());
    }

    public function testEmptyArrayYieldsPureDefaults(): void
    {
        $this->assertEquals((Config::make())->toArray(), Config::fromArray([])->toArray());
    }

    // -------------------------------------------------------------------------
    // toArray round-trip
    // -------------------------------------------------------------------------

    public function testToArrayUsesDottedKeys(): void
    {
        $array = (Config::make())->toArray();

        $this->assertArrayHasKey('trust.proxy', $array);
        $this->assertArrayHasKey('trusted.proxies', $array);
        $this->assertArrayHasKey('ip.version', $array);
        $this->assertArrayHasKey('rate.limit', $array);
        $this->assertArrayHasKey('max.hits', $array['rate.limit']);
        $this->assertArrayHasKey('storage.dir', $array['rate.limit']);
        $this->assertArrayHasKey('content.length.max', $array['request.filter']);
    }

    public function testRoundTripsThroughAnArray(): void
    {
        $config = Config::make();
        $config->trustProxy(true)->ipVersion(6);
        $config->ip->blocklist(['1.2.3.4']);
        $config->rateLimit->maxHits(5);

        $restored = Config::fromArray($config->toArray());

        $this->assertEquals($config->toArray(), $restored->toArray());
    }

    public function testSectionLookupByDottedKey(): void
    {
        $config = Config::make();

        $this->assertSame($config->rateLimit, $config->section('rate.limit'));
        $this->assertSame($config->requestFilter, $config->section('request.filter'));
        $this->assertNull($config->section('no.such.section'));
    }

    // -------------------------------------------------------------------------
    // CountryConfig gating
    // -------------------------------------------------------------------------

    public function testCountryIsNotConfiguredByDefault(): void
    {
        $this->assertFalse((Config::make())->country->isConfigured());
    }

    public function testCountryNeedsBothADatabaseAndAList(): void
    {
        $config = Config::make();

        $config->country->db('/tmp/GeoLite2-Country.mmdb');
        $this->assertFalse($config->country->isConfigured(), 'A database alone is not enough.');

        $config->country->blocklist(['CN']);
        $this->assertTrue($config->country->isConfigured());
    }

    public function testCountryListWithoutADatabaseIsNotConfigured(): void
    {
        $config = Config::make();
        $config->country->blocklist(['CN']);

        $this->assertFalse($config->country->isConfigured());
    }
}
