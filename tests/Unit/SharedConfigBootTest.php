<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Shield\Config;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Pipeline\ShieldPipeline;
use Laika\Shield\Rules\IpRule;
use Laika\Shield\Rules\RateLimitRule;
use Laika\Shield\Shield;
use Laika\Shield\Support\RequestHelper;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;
use ReflectionClass;

/**
 * Shield::boot() reads the shared Config instance.
 *
 * @covers \Laika\Shield\Shield
 * @covers \Laika\Shield\Pipeline\ShieldPipeline
 */
class SharedConfigBootTest extends TestCase
{
    private string $storageDir;

    protected function setUp(): void
    {
        Config::reset();

        $this->storageDir = sys_get_temp_dir() . '/laika_shield_shared_' . uniqid();

        $_SERVER['REMOTE_ADDR']    = '1.2.3.4';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/';
        $_GET                      = [];
        $_POST                     = [];

        // These simulate several requests in one process.
        RequestHelper::flush();
    }

    protected function tearDown(): void
    {
        Config::reset();
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

        foreach (glob($this->storageDir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->storageDir);
    }

    /**
     * boot() used to delegate to fromConfig([]), which builds a FRESH Config from
     * pure defaults — so the documented "configure then boot" flow silently did
     * nothing at all.
     */
    public function testBootAppliesValuesSetThroughTheStaticFacade(): void
    {
        Config::add('ip', ['blocklist' => ['1.2.3.4']]);
        Config::add('rate.limit', 'storage.dir', $this->storageDir);

        $this->expectException(FirewallException::class);

        Shield::boot();
    }

    public function testBootAppliesValuesSetThroughTheObjectApi(): void
    {
        Config::instance()->ip->blocklist(['1.2.3.4']);
        Config::instance()->rateLimit->storageDir($this->storageDir);

        $this->expectException(FirewallException::class);

        Shield::boot();
    }

    public function testBootPassesWhenTheSharedConfigDoesNotBlock(): void
    {
        Config::add('ip', ['blocklist' => ['9.9.9.9']]);
        Config::add('rate.limit', 'storage.dir', $this->storageDir);

        Shield::boot();

        $this->expectNotToPerformAssertions();
    }

    /**
     * Guards the signature so it cannot quietly regain a parameter.
     */
    public function testBootTakesNoParameters(): void
    {
        $this->assertSame(0, (new ReflectionMethod(Shield::class, 'boot'))->getNumberOfParameters());
    }

    public function testSharedConfigReachesTheBuiltRules(): void
    {
        Config::add('rate.limit', 'max.hits', 5);
        Config::add('ip', ['blocklist' => ['8.8.8.8']]);

        $rules = $this->rules(Shield::fromConfig(Config::instance()));

        $this->assertSame(['8.8.8.8'], $this->prop($this->ruleOf($rules, IpRule::class), 'blocklist'));
        $this->assertSame(5, $this->prop($this->ruleOf($rules, RateLimitRule::class), 'maxHits'));
    }

    /**
     * fromConfig() must stay free of global state — that is why it exists as a
     * separate entry point.
     */
    public function testFromConfigWithAnArrayIgnoresTheSharedInstance(): void
    {
        Config::add('rate.limit', 'max.hits', 5);

        $rules = $this->rules(Shield::fromConfig([]));

        $this->assertSame(
            60,
            $this->prop($this->ruleOf($rules, RateLimitRule::class), 'maxHits'),
            'fromConfig([]) must yield pure defaults, not the shared instance.'
        );
    }

    // -------------------------------------------------------------------------
    // Pipeline
    // -------------------------------------------------------------------------

    /**
     * The framework auto-registers the pipeline with no constructor argument, so
     * that path has to pick up the application's configuration.
     */
    public function testPipelineWithNoArgumentUsesTheSharedConfig(): void
    {
        Config::add('ip', ['blocklist' => ['1.2.3.4']]);
        Config::add('rate.limit', 'storage.dir', $this->storageDir);

        // The real respond() echoes and dies, which would take the test runner
        // with it — stub it the same way ShieldPipelineTest does.
        $pipeline = new class extends ShieldPipeline {
            public bool $blocked = false;

            protected function respond(FirewallException $e): never
            {
                $this->blocked = true;
                throw new PipelineTerminated();
            }
        };

        $this->assertSame(Config::instance(), $this->prop($pipeline, 'config'));

        $called = 0;
        $params = [];

        try {
            $pipeline->handle(function () use (&$called) {
                $called++;
                return 'ok';
            }, $params);
        } catch (PipelineTerminated) {
            // respond() fired, as expected for a blocked request.
        }

        $this->assertTrue($pipeline->blocked, 'The blocklisted IP must be blocked.');
        $this->assertSame(0, $called, 'A blocked request must not reach the next stage.');
    }

    public function testPipelineArrayOptionsLayerOverTheSharedConfig(): void
    {
        Config::add('rate.limit', 'max.hits', 5);

        new ShieldPipeline(['ip' => ['blocklist' => ['1.2.3.4']]]);

        // Documented side effect: the array branch fills the shared instance.
        $this->assertSame(['1.2.3.4'], Config::get('ip')['blocklist']);
        $this->assertSame(5, Config::get('rate.limit')['max.hits'], 'Existing values must survive.');
    }

    public function testPipelineWithAnExplicitConfigDoesNotTouchTheSharedInstance(): void
    {
        $config = Config::make();
        $config->ip->blocklist(['5.5.5.5']);

        $pipeline = new ShieldPipeline($config);

        $this->assertSame($config, $this->prop($pipeline, 'config'));
        $this->assertSame([], Config::get('ip')['blocklist']);
    }

    // -------------------------------------------------------------------------

    /**
     * @return object[]
     */
    private function rules(Shield $shield): array
    {
        return $this->prop($shield, 'rules');
    }

    /**
     * @param object[] $rules
     */
    private function ruleOf(array $rules, string $class): object
    {
        $found = array_values(array_filter($rules, fn ($r) => $r instanceof $class));

        $this->assertCount(1, $found, "Expected exactly one {$class}.");

        return $found[0];
    }

    /**
     * Read a property, walking up to its declaring class.
     *
     * A private property is invisible to reflection on a subclass, and the
     * pipeline assertions here run against an anonymous subclass.
     */
    private function prop(object $object, string $name): mixed
    {
        $class = new ReflectionClass($object);

        while (!$class->hasProperty($name)) {
            $class = $class->getParentClass();

            if ($class === false) {
                $this->fail("Property \${$name} not found on " . $object::class);
            }
        }

        $property = $class->getProperty($name);
        $property->setAccessible(true);

        return $property->getValue($object);
    }
}
