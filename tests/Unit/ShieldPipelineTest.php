<?php

declare(strict_types=1);

namespace Laika\Shield\Tests\Unit;

use Laika\Route\Contracts\PipelineInterface;
use Laika\Shield\ShieldConfig;
use Laika\Shield\Exceptions\FirewallException;
use Laika\Shield\Exceptions\RateLimitExceededException;
use Laika\Shield\Pipeline\ShieldPipeline;
use Laika\Shield\Support\RequestHelper;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionNamedType;

/**
 * @covers \Laika\Shield\Pipeline\ShieldPipeline
 */
class ShieldPipelineTest extends TestCase
{
    private string $storageDir;

    protected function setUp(): void
    {
        // Rate limiting is on by default now, and every test here pins REMOTE_ADDR.
        // Without a per-test directory the hit counter accumulates in the shared
        // system temp dir across suite runs, and the suite starts 429ing itself.
        $this->storageDir = sys_get_temp_dir() . '/laika_shield_test_' . uniqid();

        // Passing an array to the pipeline fills the SHARED ShieldConfig instance, so
        // without this one test's blocklist survives into the next.
        ShieldConfig::reset();

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
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $this->rmdir($this->storageDir);
        ShieldConfig::reset();
    }

    /**
     * The regression test for the middleware fail-open: a blocked request used to
     * fall through the catch and still invoke the next stage.
     */
    public function testBlockedRequestNeverReachesTheNextStage(): void
    {
        $pipeline = $this->pipeline(['ip' => ['blocklist' => ['1.2.3.4']]]);

        $called = 0;
        $next   = function () use (&$called) {
            $called++;
            return 'controller output';
        };

        $params = [];
        $pipeline->handle($next, $params);

        $this->assertSame(0, $called, 'A blocked request must not run the rest of the chain.');
        $this->assertCount(1, $pipeline->responses);
        $this->assertInstanceOf(FirewallException::class, $pipeline->responses[0]);
    }

    public function testBlockedRequestPayloadCarriesStatusMessageAndIp(): void
    {
        $pipeline = $this->pipeline(['ip' => ['blocklist' => ['1.2.3.4']]]);

        $params = [];
        $pipeline->handle(fn () => 'controller output', $params);

        $payload = json_decode($pipeline->responses[0]->payload(), true);

        $this->assertSame(403, $payload['status']);
        $this->assertSame('1.2.3.4', $payload['ip']);
        $this->assertStringContainsString('1.2.3.4', $payload['message']);
    }

    public function testAllowedRequestRunsTheChainExactlyOnce(): void
    {
        $pipeline = $this->pipeline(['ip' => ['blocklist' => ['9.9.9.9']]]);

        $called = 0;
        $next   = function () use (&$called) {
            $called++;
            return 'controller output';
        };

        $params = [];
        $result = $pipeline->handle($next, $params);

        $this->assertSame(1, $called);
        $this->assertSame('controller output', $result);
        $this->assertSame([], $pipeline->responses);
    }

    public function testRateLimitBlockCarriesRetryAfter(): void
    {
        $pipeline = $this->pipeline([
            'rate.limit' => ['max.hits' => 1, 'window' => 60],
        ]);

        $params = [];
        $pipeline->handle(fn () => 'ok', $params);   // first hit passes
        $pipeline->handle(fn () => 'ok', $params);   // second hit is blocked

        $this->assertCount(1, $pipeline->responses);
        $this->assertInstanceOf(RateLimitExceededException::class, $pipeline->responses[0]);

        $payload = json_decode($pipeline->responses[0]->payload(), true);
        $this->assertSame(429, $payload['status']);
        $this->assertGreaterThan(0, $payload['retry_after']);
    }

    /**
     * laika-framework is not installed here (it depends on this package, so this
     * package cannot depend on it back). Assert the contract shape directly —
     * a by-value $params or a changed return type would only fatal in production.
     */
    public function testHandleMatchesTheFrameworkPipelineContract(): void
    {
        $method = new ReflectionMethod(ShieldPipeline::class, 'handle');
        $params = $method->getParameters();

        $this->assertTrue($method->isPublic());
        $this->assertCount(2, $params);

        $this->assertSame('next', $params[0]->getName());
        $this->assertSame('callable', (string) $params[0]->getType());
        $this->assertFalse($params[0]->isPassedByReference());

        $this->assertSame('params', $params[1]->getName());
        $this->assertSame('array', (string) $params[1]->getType());
        $this->assertTrue(
            $params[1]->isPassedByReference(),
            '$params must be by reference to satisfy PipelineInterface.'
        );

        $return = $method->getReturnType();
        $this->assertInstanceOf(ReflectionNamedType::class, $return);
        $this->assertSame('string', $return->getName());
        $this->assertTrue($return->allowsNull());

        $this->assertTrue(is_subclass_of(ShieldPipeline::class, PipelineInterface::class));
    }

    /**
     * @param array<string,mixed> $config
     */
    private function pipeline(array $config): ShieldPipeline
    {
        // Keep every rate-limit counter inside this test's own directory.
        $config['rate.limit'] = ($config['rate.limit'] ?? []) + ['storage.dir' => $this->storageDir];

        return new class ($config) extends ShieldPipeline {
            /** @var FirewallException[] */
            public array $responses = [];

            protected function respond(FirewallException $e): never
            {
                $this->responses[] = $e;

                // Stand in for the die() so the block path stays assertable
                // in-process. The production override is the only difference.
                throw new PipelineTerminated();
            }

            public function handle(callable $next, array &$params): ?string
            {
                try {
                    return parent::handle($next, $params);
                } catch (PipelineTerminated) {
                    return null;
                }
            }
        };
    }

    private function rmdir(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($dir);
    }
}
