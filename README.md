# 🛡️ Laika Shield

**Laika Shield** is the firewall layer for the [Laika PHP Framework](https://github.com/laikait/laika-framework) — IP and country filtering, rate limiting, SQL injection and XSS detection, and request filtering.

[![Tests](https://github.com/laikait/laika-shield/actions/workflows/test.yml/badge.svg)](https://github.com/laikait/laika-shield/actions)
[![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌍 Country Blocking | Block or allowlist entire countries via MaxMind GeoLite2 |
| 🚫 IP Blocking | Block individual IPs or CIDR ranges |
| ✅ IP Allowlisting | Restrict access to specific IPs/ranges only |
| 🔢 IP Version Filtering | Allow only IPv4 or only IPv6 connections |
| ⏱️ Rate Limiting | Limit requests per IP per time window |
| 💉 SQL Injection Detection | Block common SQLi attack payloads |
| 🐛 XSS Detection | Block cross-site scripting attempts |
| 🔍 Request Filtering | Filter by HTTP method, URI, User-Agent, headers, and body size |

---

## 📦 Installation

Laika Shield ships as part of the framework — `laikait/laika-framework` already
requires it, so there is usually nothing to install.

To pull it into a project directly:

```bash
composer require laikait/laika-shield
```

**Requires** PHP 8.1+ and `geoip2/geoip2`. Country blocking additionally needs a
MaxMind GeoLite2-Country database, which is **not** bundled — see
[Country Blocking](#-country-blocking).

---

## 🚀 Quick Start

### 1. Register the pipeline

Add `ShieldPipeline` to your route pipeline stack — **first**, ahead of everything
else. It is only a firewall if nothing has run yet.

```php
use Laika\Shield\Pipeline\ShieldPipeline;

// In your pipeline registration
ShieldPipeline::class,
```

There is no config file to publish — the defaults are already complete, so the line
above gives you a working firewall.

### 2. Adjust the configuration

```php
use Laika\Shield\ShieldConfig;
use Laika\Shield\Pipeline\ShieldPipeline;

// ShieldConfig is a singleton — configure it once and everything
// (ShieldPipeline, Shield::boot()) picks it up.
ShieldConfig::ip()->blocklist(['1.2.3.4', '10.0.0.0/8']);
ShieldConfig::rateLimit()->maxHits(30)->window(120);
ShieldConfig::xss()->skipKeys(['post_body']);
ShieldConfig::requestFilter()->requiredHeaders(['x-api-key']);

// The three top-level scalars live on the instance:
ShieldConfig::instance()->trustProxy(true)->trustedProxies(['10.0.0.0/8']);

new ShieldPipeline();
```

A blocked request emits its JSON body and terminates. It never reaches the rest of
the chain, so no downstream pipeline — auth, logging, database writes — runs for a
request the firewall rejected.

> **Upgrading from 1.2.x:** `Laika\Shield\Http\ShieldMiddleware` has been removed.
> It fell through its own catch block and let blocked requests reach the application.
> Replace it with `ShieldPipeline` as above.

### 3. Or use the static API

```php
use Laika\Shield\Shield;
use Laika\Shield\ShieldConfig;

// Shield::boot() takes no arguments — it reads the shared ShieldConfig instance.
ShieldConfig::add('ip', ['blocklist' => ['1.2.3.4']]);
ShieldConfig::add('rate.limit', 'max.hits', 30);

Shield::boot();

// To run a DETACHED configuration instead — ShieldConfig::make() is not the
// shared instance, so boot() will not see it:
$config = ShieldConfig::make();
$config->ip->blocklist(['1.2.3.4']);

Shield::fromConfig($config)->run();
```

### 4. Or use the fluent builder

```php
use Laika\Shield\Shield;

(new Shield())
    ->trustProxy(true, trustedProxies: ['10.0.0.0/8'])
    ->blockCountries('/path/to/GeoLite2-Country.mmdb', blocklist: ['CN', 'RU'])
    ->blockIps(['1.2.3.4', '10.10.0.0/16'])
    ->allowIps(['203.0.113.0/24'])
    ->requireIpVersion(4) // IPv4 only
    ->rateLimit(maxHits: 100, windowSecs: 60)
    ->detectSqlInjection(skipKeys: ['password'])   // strict: false by default
    ->detectXss(skipKeys: ['html_content'])
    ->filterRequests(
        blockedMethods: ['TRACE', 'CONNECT'],
        blockedUserAgentPatterns: ['/sqlmap/i', '/nikto/i'],
    )
    ->run();
```

---

## ⚙️ Configuration Reference

Every option lives on a typed object with a fluent accessor: call it with no argument
to read, with one to write. Defaults are declared on the properties themselves.

```php
// ── Top level (instance only — see the note below) ───────────────────────
ShieldConfig::instance()->trustProxy(false);      // consult proxy headers at all
ShieldConfig::instance()->trustedProxies([]);     // CIDRs of YOUR proxies
ShieldConfig::instance()->ipVersion(null);        // 4, 6, or null for both

// ── IP filtering ─────────────────────────────────────────────────────────
ShieldConfig::ip()->blocklist([]);           // denied IPs / CIDR ranges
ShieldConfig::ip()->allowlist([]);           // when non-empty, ONLY these are permitted

// ── Rate limiting ────────────────────────────────────────────────────────
ShieldConfig::rateLimit()->maxHits(60);      // requests per window, per IP
ShieldConfig::rateLimit()->window(60);       // window size in seconds
ShieldConfig::rateLimit()->storageDir(null); // null = system temp directory

// ── SQL injection detection ──────────────────────────────────────────────
ShieldConfig::sqlInjection()->skipKeys([]);  // input keys never scanned
ShieldConfig::sqlInjection()->scanBody(true);
ShieldConfig::sqlInjection()->strict(false); // see Tuning The Detectors

// ── XSS detection ────────────────────────────────────────────────────────
ShieldConfig::xss()->skipKeys([]);
ShieldConfig::xss()->scanBody(true);
ShieldConfig::xss()->scanHeaders(false);

// ── Request filtering ────────────────────────────────────────────────────
ShieldConfig::requestFilter()->blockedMethods(['TRACE', 'CONNECT']);
ShieldConfig::requestFilter()->blockedUriPatterns([]);
ShieldConfig::requestFilter()->blockedUserAgents(['/sqlmap/i', '/nikto/i', ...]);
ShieldConfig::requestFilter()->requiredHeaders([]);
ShieldConfig::requestFilter()->blockedHeaderValues([]);
ShieldConfig::requestFilter()->contentLengthMax(null);
ShieldConfig::requestFilter()->contentLengthMin(null);

// ── Country blocking ─────────────────────────────────────────────────────
ShieldConfig::country()->db('');             // path to GeoLite2-Country.mmdb
ShieldConfig::country()->blocklist([]);
ShieldConfig::country()->allowlist([]);
```

Accessors chain, and reading is the same method without an argument:

```php
ShieldConfig::rateLimit()->maxHits(30)->window(120);

$hits = ShieldConfig::rateLimit()->maxHits();   // 30
```

The six section accessors — `ip()`, `rateLimit()`, `sqlInjection()`, `xss()`,
`requestFilter()`, `country()` — are static because there is only one configuration.
The three top-level scalars (`trustProxy`, `trustedProxies`, `ipVersion`) stay on the
instance: they are declared as instance methods, and PHP will not let a method be both
static and non-static under one name.

Nullable options can be set back to null — `storageDir`, `contentLengthMax`,
`contentLengthMin` and `ipVersion` all accept it as a real value.

### Arrays still work

`ShieldPipeline` and `Shield::fromConfig()` accept a plain array, which is applied
**over** the defaults rather than replacing them. Supplying one option in a section
leaves the rest of that section alone:

```php
Shield::fromConfig([
    'request.filter' => ['content.length.max' => 2048],
])->run();
// blocked.methods is still ['TRACE', 'CONNECT']
```

`Shield::boot()` takes no arguments at all — it always reads the shared `ShieldConfig`
instance, so configure that first with `ShieldConfig::add()` or `ShieldConfig::instance()`.

Note the difference in where the defaults come from: `fromConfig()` layers an array
over a **fresh** set of defaults and never touches global state, which keeps it
predictable and testable. `ShieldPipeline` layers an array over the **shared**
instance, so pipeline options combine with whatever the application configured.

---

### ShieldConfig is a singleton

`ShieldConfig` has no public constructor. There is exactly one shared configuration, and
that is what `Shield::boot()` and `ShieldPipeline` read:

```php
ShieldConfig::rateLimit()->maxHits(30);
Shield::boot();                      // sees it
```

The static section accessors are shortcuts onto that same shared instance —
`ShieldConfig::rateLimit()` is exactly `ShieldConfig::instance()->rateLimit`.

If you need a throwaway configuration — for a test, or to run one request under
different rules — `ShieldConfig::make()` gives you a **detached** object. `boot()` will not
see it, so run it explicitly:

```php
$config = ShieldConfig::make();
$config->rateLimit->maxHits(1);       // note: property, not ShieldConfig::rateLimit()

Shield::fromConfig($config)->run();   // only this sees it
```

⚠️ The static accessors always resolve the **shared** instance. If you are holding a
detached config, reach its sections through the object (`$config->rateLimit`) —
`ShieldConfig::rateLimit()` would configure the shared one instead.

| Call | Returns | Seen by `Shield::boot()` |
|---|---|---|
| `ShieldConfig::instance()` | the shared configuration | ✅ yes |
| `ShieldConfig::make()` | a new detached configuration | ❌ no — use `fromConfig()` |
| `ShieldConfig::fromArray([...])` | a detached configuration from an array | ❌ no — use `fromConfig()` |
| `ShieldConfig::rateLimit()` etc. | a section of the **shared** configuration | ✅ yes |
| `new ShieldConfig()` | — | `Error`: constructor is not public |

---

## 🔧 ShieldConfig Class

`ShieldConfig` also exposes a static, array-keyed API over one shared instance. It is kept
for compatibility — the `ShieldConfig` relay is bound to it — and remains handy for
one-off tweaks during bootstrap. New code should prefer the object API above.

```php
use Laika\Shield\ShieldConfig;
use Laika\Shield\Shield;

// Top-level scalar
ShieldConfig::add('trust.proxy', true);

// Top-level array merge
ShieldConfig::add('ip', ['blocklist' => ['1.2.3.4', '10.0.0.0/8']]);

// Sub-key update (simplest way to change a nested value)
ShieldConfig::add('rate.limit', 'max.hits', 30);
ShieldConfig::add('sql.injection', 'skip.keys', ['password', 'token']);
ShieldConfig::add('xss', 'skip.keys', ['content', 'body']);
ShieldConfig::add('request.filter', 'content.length.max', 2048);

// Shield::boot() reads this shared instance
Shield::boot();
```

### ShieldConfig API

| Method | Description |
|---|---|
| `ShieldConfig::add(string $key, mixed $value)` | Set or merge a top-level config key |
| `ShieldConfig::add(string $key, string $subKey, mixed $value)` | Set or merge a specific sub-key |
| `ShieldConfig::get()` | Return the full config array |
| `ShieldConfig::get(string $key)` | Return the value of a single key |
| `ShieldConfig::has(string $key)` | Check if a key exists |
| `ShieldConfig::keys()` | Return all top-level config keys |
| `ShieldConfig::reset()` | Reset the shared instance back to defaults |
| `ShieldConfig::instance()` | The shared `ShieldConfig` object behind the static API |

---

## 🏗️ Architecture

```
src/
├── Shield.php                          # Main firewall engine (static + fluent API)
├── ShieldConfig.php                          # Configuration object + static facade
├── Contract/
│   ├── RuleInterface.php              # Individual Rule Interface
│   └── DetectorInterface.php          # Value inspector / classifier contract
├── Rules/
│   ├── IpRule.php                     # IP blocking / allowlisting
│   ├── IpVersionRule.php              # IPv4 / IPv6 enforcement
│   ├── RateLimitRule.php              # Rate limiting
│   ├── CountryRule.php                # Country blocking / allowlisting
│   ├── SqlInjectionRule.php           # SQL injection protection
│   ├── XssRule.php                    # XSS protection
│   └── RequestFilterRule.php          # General request filtering
├── Detectors/
│   ├── GeoIpDetector.php              # MaxMind GeoLite2 country resolver
│   ├── SqlInjectionDetector.php       # SQLi regex patterns engine
│   └── XssDetector.php                # XSS regex patterns engine
├── Pipeline/
│   └── ShieldPipeline.php             # Laika route pipeline integration
├── Support/
│   ├── IpHelper.php                   # IP validation, CIDR, version detection
│   ├── RateLimiter.php                # File-based rate limit store
│   └── RequestHelper.php              # Request data extraction helpers
├── Exceptions/
│   ├── FirewallException.php          # Base firewall exception (HTTP 403)
│   └── RateLimitExceededException.php # Rate limit exception (HTTP 429)
└── ShieldConfig/
    ├── SectionConfig.php              # Fluent accessor base for the sections
    ├── IpConfig.php                   # ip.blocklist / ip.allowlist
    ├── RateLimitConfig.php            # rate.limit.*
    ├── SqlInjectionConfig.php         # sql.injection.*
    ├── XssConfig.php                  # xss.*
    ├── RequestFilterConfig.php        # request.filter.*
    └── CountryConfig.php              # country.*
```

---

## 🔌 Writing Custom Rules

Implement `RuleInterface` to create your own firewall rules:

```php
use Laika\Shield\Contract\RuleInterface;

class CountryBlockRule implements RuleInterface
{
    public function passes(): bool
    {
        // Your logic here
        return true;
    }

    public function message(): string
    {
        return 'Access Denied From Your Country.';
    }

    public function statusCode(): int
    {
        return 403;
    }

    public function additionalHeader(): void
    {
        return;
    }
}

// Register it
(new Shield())
    ->addRule(new CountryBlockRule())
    ->run();
```

---

## 🧪 Running Tests

```bash
composer install
vendor/bin/phpunit
```

---

## 🌐 IP Version Detection

Shield exposes `IpHelper` for standalone IP utilities:

```php
use Laika\Shield\Support\IpHelper;

IpHelper::version('8.8.8.8');          // 4
IpHelper::version('2001:db8::1');      // 6
IpHelper::version('invalid');          // null

IpHelper::isV4('192.168.1.1');         // true
IpHelper::isV6('::1');                 // true
IpHelper::isPrivate('10.0.0.1');       // true
IpHelper::isLoopback('127.0.0.1');     // true
IpHelper::inCidr('192.168.1.5', '192.168.1.0/24'); // true

// Resolve real client IP (proxy-aware)
$ip = IpHelper::resolve(trustProxy: true, trustedProxies: ['10.0.0.0/8']);
```

---

## 🔐 Trusting Proxies

Forwarded headers are attacker-controlled. Anyone can send
`X-Forwarded-For: 8.8.8.8`, so believing the wrong one turns every IP rule into a
suggestion.

Shield only consults them when `trust.proxy` is on, and:

- `CF-Connecting-IP` / `X-Real-IP` are believed **only** when the connecting peer is
  listed in `trusted.proxies`. A direct client can set these headers just as easily
  as a proxy can.
- `X-Forwarded-For` is walked **right to left**, discarding hops that match
  `trusted.proxies`, and the first remaining address wins. The leftmost entry — the
  one a client fully controls — is never trusted.
- With `trusted.proxies` empty, the rightmost `X-Forwarded-For` entry is used, since
  that is the only entry your own proxy wrote.

```php
'trust.proxy'     => true,
'trusted.proxies' => ['10.0.0.0/8', '173.245.48.0/20'],
```

If your app is not behind a proxy, leave `trust.proxy => false`.

---

## 🌍 Country Blocking

The GeoLite2 database is **not** distributed with this package — it is
MaxMind-licensed and roughly 9.5 MB. Fetch it with your own licence key:

```bash
# https://github.com/maxmind/geoipupdate
geoipupdate -f GeoIP.conf -d /var/lib/GeoIP
```

Then point the config at it:

```php
'country' => [
    'db'        => '/var/lib/GeoIP/GeoLite2-Country.mmdb',
    'blocklist' => ['CN', 'RU'],
    'allowlist' => [],
],
```

A missing or unreadable database does not block anyone and does not raise an error —
requests simply pass the country check.

---

## 🎯 Tuning The Detectors

The detectors match SQL and HTML **syntax**, not vocabulary. Words like `select`,
`sleep`, `drop table` or `#42` in ordinary prose are not treated as attacks.

`strict` mode adds keyword-only SQL patterns. It **will** flag normal sentences, so
enable it only for fields that never carry free text:

```php
'sql.injection' => [
    'skip.keys' => ['bio', 'comment'],  // never scanned
    'strict'    => false,               // recommended
],
```

For rich-text or markup-bearing fields, use `skip.keys` rather than weakening the
patterns for everything.

---

## 📄 License

MIT © [Laika IT](https://github.com/laikait)

GeoLite2 data, if you use it, is © MaxMind and governed by the
[GeoLite2 End User Licence Agreement](https://www.maxmind.com/en/geolite2/eula).