# 🛡️ Laika Shield

**Laika Shield** is a powerful, zero-dependency firewall middleware for the [Laika PHP Framework](https://github.com/laikait/laika-framework).

[![Tests](https://github.com/laikait/laika-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/laikait/laika-shield/actions)
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

```bash
composer require laikait/laika-shield
```

---

## 🚀 Quick Start

### 1. Publish the config file

Copy `vendor/laikait/laika-shield/src/Storage/config.sample.php` to your project's `Storage/` directory.

### 2. Register as Middleware

In your Laika application bootstrap or middleware pipeline:

```php
use Laika\Shield\Http\ShieldMiddleware;

$config = require __DIR__ . '/../Storage/config.sample.php';

$middleware = new ShieldMiddleware($config);
$middleware->handle(function () {
    // Your controller / next middleware
});
```

### 3. Or use the static API

```php
use Laika\Shield\Shield;
use Laika\Shield\Config;

// Auto-loads defaults from Config — no argument needed
Shield::boot();

// Or pass a custom config array
Shield::boot(Config::get());
```

### 4. Or use the fluent builder

```php
use Laika\Shield\Shield;

(new Shield())
    ->trustProxy()
    ->blockCountries('/path/to/GeoLite2-Country.mmdb', blocklist: ['CN', 'RU'])
    ->blockIps(['1.2.3.4', '10.10.0.0/16'])
    ->allowIps(['203.0.113.0/24'])
    ->requireIpVersion(4) // IPv4 only
    ->rateLimit(maxHits: 100, windowSecs: 60)
    ->detectSqlInjection(skipKeys: ['password'])
    ->detectXss(skipKeys: ['html_content'])
    ->filterRequests(
        blockedMethods: ['TRACE', 'CONNECT'],
        blockedUserAgentPatterns: ['/sqlmap/i', '/nikto/i'],
    )
    ->run();
```

---

## ⚙️ Configuration Reference

```php
// Storage/config.sample.php
return [

    // Country blocking (requires MaxMind GeoLite2-Country.mmdb)
    'country' => [
        'db'        => '/path/to/GeoLite2-Country.mmdb',
        'blocklist' => ['CN', 'RU'],  // block these countries
        'allowlist' => [],            // when non-empty, ONLY these countries allowed
    ],

    // Trust proxy headers (X-Forwarded-For, CF-Connecting-IP, etc.)
    'trust.proxy' => false,

    // IP blocking and allowlisting
    'ip' => [
        'blocklist' => ['1.2.3.4', '192.168.100.0/24'],
        'allowlist' => [],  // when non-empty, ONLY these IPs are allowed
    ],

    // Only allow IPv4 (4) or IPv6 (6). null = both allowed.
    'ip.version' => null,

    // Rate limiting
    'rate.limit' => [
        'max.hits'    => 60,    // requests
        'window'      => 60,    // seconds
        'storage.dir' => null,  // defaults to sys_get_temp_dir()
    ],

    // SQL injection detection
    'sql.injection' => [
        'skip.keys' => [],      // input keys to skip
        'scan.body' => true,    // also scan raw body (JSON, XML)
        'strict'    => true,    // also block standalone DML (SELECT/INSERT/UPDATE/DELETE/DROP)
    ],

    // XSS detection
    'xss' => [
        'skip.keys'    => [],
        'scan.headers' => false,
        'scan.body'    => true,
    ],

    // Request filtering
    'request.filter' => [
        'blocked.methods'       => ['TRACE', 'CONNECT'],
        'blocked.uri.patterns'  => ['/\/\.env$/i'],
        'blocked.user.agents'   => ['/sqlmap/i', '/nikto/i'],
        'headers.required'      => [],
        'blocked.header.values' => [],
        'content.length.max'    => null,
        'content.length.min'    => null,
    ],
];
```

---

## 🔧 Config Class

The `Config` class provides a fluent API to load and modify the default configuration at runtime — without editing the config file directly.

```php
use Laika\Shield\Config;
use Laika\Shield\Shield;

// Top-level scalar
Config::add('trust.proxy', true);

// Top-level array merge
Config::add('ip', ['blocklist' => ['1.2.3.4', '10.0.0.0/8']]);

// Sub-key update (simplest way to change a nested value)
Config::add('rate.limit', 'max.hits', 30);
Config::add('sql.injection', 'skip.keys', ['password', 'token']);
Config::add('xss', 'skip.keys', ['content', 'body']);
Config::add('request.filter', 'content.length.max', 2048);

// Boot uses Config automatically when no array is passed
Shield::boot();
```

### Config API

| Method | Description |
|---|---|
| `Config::add(string $key, mixed $value)` | Set or merge a top-level config key |
| `Config::add(string $key, string $subKey, mixed $value)` | Set or merge a specific sub-key |
| `Config::get()` | Return the full config array |
| `Config::get(string $key)` | Return the value of a single key |
| `Config::has(string $key)` | Check if a key exists |
| `Config::keys()` | Return all top-level config keys |
| `Config::reset()` | Reset the singleton (useful in tests) |

---

## 🏗️ Architecture

```
src/
├── Shield.php                          # Main firewall engine (static + fluent API)
├── Config.php                          # Runtime configuration manager
├── Interfaces/
│   ├── FirewallInterface.php           # Core Firewall Interface
│   ├── RuleInterface.php               # Individual Rule Interface
│   └── DetectorInterface.php          # Pattern Detector Interface
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
├── Http/
│   └── ShieldMiddleware.php           # Laika MMC middleware integration
├── Support/
│   ├── IpHelper.php                   # IP validation, CIDR, version detection
│   ├── RateLimiter.php                # File-based rate limit store
│   └── RequestHelper.php              # Request data extraction helpers
├── Exceptions/
│   ├── FirewallException.php          # Base firewall exception (HTTP 403)
│   └── RateLimitExceededException.php # Rate limit exception (HTTP 429)
└── Storage/
    └── config.sample.php              # Default configuration template
```

---

## 🔌 Writing Custom Rules

Implement `RuleInterface` to create your own firewall rules:

```php
use Laika\Shield\Interfaces\RuleInterface;

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
$ip = IpHelper::resolve(trustProxy: true);
```

---

## 📄 License

MIT © [Laika IT](https://github.com/laikait)