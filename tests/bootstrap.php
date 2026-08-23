<?php

declare(strict_types=1);

// Pipeline classes carry the framework's direct-access guard, so APP_PATH must
// exist before any of them are autoloaded.
defined('APP_PATH') || define('APP_PATH', dirname(__DIR__));

require dirname(__DIR__) . '/vendor/autoload.php';
