<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Config;
use Laika\Shield\Rules\CountryRule;
use Laika\Shield\Rules\IpRule;
use Laika\Shield\Rules\IpVersionRule;
use Laika\Shield\Rules\RateLimitRule;
use Laika\Shield\Rules\RequestFilterRule;
use Laika\Shield\Rules\SqlInjectionRule;
use Laika\Shield\Rules\XssRule;
use Laika\Shield\Shield;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * @covers \Laika\Shield\Shield
 */
class ShieldBootTest extends TestCase
{
    protected function setUp(): void
    {
        Config::reset();

        $_SERVER['REMOTE_ADDR']    = '203.0.113.9';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';
    }

    /**
     * boot() passed scan.headers and scan.body positionally into
     * ($scanBody, $scanHeaders), silently inverting both: raw JSON bodies went
     * unscanned while headers were scanned.
     */
    public function testXssScanFlagsFollowTheConfigKeys(): void
    {
        $rule = $this->buildXssRule(['skip.keys' => [], 'scan.body' => true, 'scan.headers' => false]);

        $this->assertTrue($this->prop($rule, 'scanBody'), 'scan.body => true must enable body scanning.');
        $this->assertFalse($this->prop($rule, 'scanHeaders'), 'scan.headers => false must disable header scanning.');
    }

    public function testXssScanFlagsFollowTheConfigKeysWhenInverted(): void
    {
        $rule = $this->buildXssRule(['skip.keys' => [], 'scan.body' => false, 'scan.headers' => true]);

        $this->assertFalse($this->prop($rule, 'scanBody'));
        $this->assertTrue($this->prop($rule, 'scanHeaders'));
    }

    public function testSkipKeysReachTheRule(): void
    {
        $rule = $this->buildXssRule(['skip.keys' => ['content'], 'scan.body' => true, 'scan.headers' => false]);

        $this->assertSame(['content'], $this->prop($rule, 'skipKeys'));
    }

    /**
     * Every configured section is always registered now: a Config carries complete
     * defaults, so overrides adjust the firewall rather than switching it on.
     */
    public function testDefaultsRegisterTheFullRuleSet(): void
    {
        $classes = array_map(fn ($r) => $r::class, $this->rulesFor([]));

        $this->assertContains(IpRule::class, $classes);
        $this->assertContains(RateLimitRule::class, $classes);
        $this->assertContains(SqlInjectionRule::class, $classes);
        $this->assertContains(XssRule::class, $classes);
        $this->assertContains(RequestFilterRule::class, $classes);
    }

    public function testPartialArrayStillRegistersTheFullRuleSet(): void
    {
        $classes = array_map(fn ($r) => $r::class, $this->rulesFor(['ip' => ['blocklist' => ['1.2.3.4']]]));

        $this->assertContains(IpRule::class, $classes);
        $this->assertContains(RateLimitRule::class, $classes);
        $this->assertContains(XssRule::class, $classes);
        $this->assertNotContains(CountryRule::class, $classes, 'No GeoIP database is configured.');
    }

    /**
     * A null ip.version allows both versions, making the rule a no-op. Skip it
     * rather than registering one that can never fail.
     */
    public function testIpVersionRuleIsSkippedWhenNull(): void
    {
        $classes = array_map(fn ($r) => $r::class, $this->rulesFor([]));
        $this->assertNotContains(IpVersionRule::class, $classes);

        $classes = array_map(fn ($r) => $r::class, $this->rulesFor(['ip.version' => 4]));
        $this->assertContains(IpVersionRule::class, $classes);
    }

    public function testAcceptsAConfigObject(): void
    {
        $config = Config::make();
        $config->xss->skipKeys(['content'])->scanHeaders(true);

        $rules = $this->prop(\Laika\Shield\Shield::fromConfig($config), 'rules');
        $found = array_values(array_filter($rules, fn ($r) => $r instanceof XssRule));

        $this->assertCount(1, $found);
        $this->assertSame(['content'], $this->prop($found[0], 'skipKeys'));
        $this->assertTrue($this->prop($found[0], 'scanHeaders'));
    }

    /**
     * Building a CountryRule opens a multi-megabyte GeoIP reader, so an empty
     * blocklist and allowlist must not construct one at all.
     */
    public function testCountryRuleIsSkippedWhenNoListIsConfigured(): void
    {
        $rules = $this->rulesFor([
            'country' => ['db' => __DIR__ . '/nonexistent.mmdb', 'blocklist' => [], 'allowlist' => []],
        ]);

        $this->assertSame([], array_filter($rules, fn ($r) => $r instanceof CountryRule));
    }

    public function testCountryRuleIsBuiltWhenABlocklistExists(): void
    {
        $rules = $this->rulesFor([
            'country' => ['db' => __DIR__ . '/nonexistent.mmdb', 'blocklist' => ['CN'], 'allowlist' => []],
        ]);

        $this->assertCount(1, array_filter($rules, fn ($r) => $r instanceof CountryRule));
    }

    /**
     * A missing database must not fatal the request. It used to throw
     * InvalidDatabaseException straight out of the rule constructor.
     */
    public function testMissingGeoIpDatabaseDoesNotBlockOrThrow(): void
    {
        $rule = new CountryRule(__DIR__ . '/nonexistent.mmdb', ['CN'], []);

        $this->assertTrue($rule->passes());
    }

    private function buildXssRule(array $xssConfig): XssRule
    {
        $rules = $this->rulesFor(['xss' => $xssConfig]);
        $found = array_values(array_filter($rules, fn ($r) => $r instanceof XssRule));

        $this->assertCount(1, $found, 'Expected exactly one XssRule to be registered.');

        return $found[0];
    }

    /**
     * Exercise the real config-to-rule wiring from Shield::fromConfig().
     *
     * @param array<string,mixed> $config
     * @return object[]
     */
    private function rulesFor(array $config): array
    {
        return $this->prop(Shield::fromConfig($config), 'rules');
    }

    protected function tearDown(): void
    {
        Config::reset();
    }

    private function prop(object $object, string $name): mixed
    {
        $property = new ReflectionProperty($object, $name);
        $property->setAccessible(true);

        return $property->getValue($object);
    }
}
