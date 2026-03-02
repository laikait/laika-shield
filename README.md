# 🛡️ Laika Shield

**Laika Shield** is a powerful, zero-dependency firewall middleware for the [Laika PHP Framework](https://github.com/laikait/laika-framework).

[![Tests](https://github.com/laikait/laika-shield/actions/workflows/tests.yml/badge.svg)](https://github.com/laikait/laika-shield/actions)
[![PHP](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## ✨ Features

| Feature | Description |
|---|---|
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

Copy `vendor/laikait/laika-shield/src/Config/shield.php` to your project's `config/` directory.

### 2. Register as Middleware

In your Laika application bootstrap or middleware pipeline:

```php
use Laika\Shield\Http\ShieldMiddleware;

$config = require __DIR__ . '/../config/shield.php';

$middleware = new ShieldMiddleware($config);
$middleware->handle(function () {
    // Your controller / next middleware
});
```

### 3. Or use the static API

```php
use Laika\Shield\Shield;

Shield::boot(require 'config/shield.php');
```

### 4. Or use the fluent builder

```php
use Laika\Shield\Shield;

(new Shield())
    ->trustProxy()
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
// config/shield.php
return [

    // Trust proxy headers (X-Forwarded-For, CF-Connecting-IP, etc.)
    'trust_proxy' => false,

    // IP blocking and allowlisting
    'ip' => [
        'blocklist' => ['1.2.3.4', '192.168.100.0/24'],
        'allowlist' => [],  // when non-empty, ONLY these IPs are allowed
    ],

    // Only allow IPv4 (4) or IPv6 (6). null = both allowed.
    'ip_version' => null,

    // Rate limiting
    'rate_limit' => [
        'max_hits'    => 60,    // requests
        'window'      => 60,    // seconds
        'storage_dir' => null,  // defaults to sys_get_temp_dir()
    ],

    // SQL injection detection
    'sql_injection' => [
        'skip_keys' => [],      // input keys to skip
        'scan_body' => true,    // also scan raw body (JSON, XML)
    ],

    // XSS detection
    'xss' => [
        'skip_keys'    => [],
        'scan_headers' => false,
        'scan_body'    => true,
    ],

    // Request filtering
    'request_filter' => [
        'blocked_methods'        => ['TRACE', 'CONNECT'],
        'blocked_uri_patterns'   => ['/\/\.env$/i'],
        'blocked_user_agents'    => ['/sqlmap/i', '/nikto/i'],
        'required_headers'       => [],
        'blocked_header_values'  => [],
        'max_content_length'     => null,
        'min_content_length'     => null,
    ],
];
```

---

## 🏗️ Architecture

```
src/
├── Shield.php                          # Main firewall engine (static + fluent API)
├── Interfaces/
│   ├── FirewallInterface.php           # Core firewall contract
│   ├── RuleInterface.php              # Individual rule contract
│   └── DetectorInterface.php          # Pattern detector contract
├── Rules/
│   ├── IpRule.php                     # IP blocking / allowlisting
│   ├── IpVersionRule.php              # IPv4 / IPv6 enforcement
│   ├── RateLimitRule.php              # Rate limiting
│   ├── SqlInjectionRule.php           # SQL injection protection
│   ├── XssRule.php                    # XSS protection
│   └── RequestFilterRule.php          # General request filtering
├── Detectors/
│   ├── SqlInjectionDetector.php       # SQLi regex patterns engine
│   └── XssDetector.php                # XSS regex patterns engine
├── Http/
│   └── ShieldMiddleware.php           # Laika MMC middleware integration
├── Support/
│   ├── IpHelper.php                   # IP validation, CIDR, version detection
│   ├── RateLimiter.php                # File-based rate limit store
│   └── RequestHelper.php             # Request data extraction helpers
├── Exceptions/
│   ├── FirewallException.php          # Base firewall exception (HTTP 403)
│   └── RateLimitExceededException.php # Rate limit exception (HTTP 429)
└── Config/
    └── shield.php                     # Default configuration template
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
        return 'Access denied from your country.';
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
