<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Run by FreshRequestCostTest in a new PHP process: what the app loads and
 * queries for one failed login. Prints one JSON object.
 *
 * Usage: php failed-login.php <server root>
 */

use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\IDBConnection;
use OCP\Server;

[, $root] = $argv;
$_SERVER['REMOTE_ADDR'] = '203.0.113.72';

require $root . '/lib/base.php';

$classes = static fn (): array => array_values(array_filter(
	array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits()),
	static fn (string $class): bool => str_starts_with($class, 'OCA\\IntrusionDetection\\'),
));
$queries = static fn (): int => (int)Server::get(IDBConnection::class)->getInner()->getStats()['executed'];

Server::get(IAppConfig::class)->getValueString('core', 'vendor', '');
$dispatcher = Server::get(IEventDispatcher::class);
$before = $classes();
$queriesBefore = $queries();
$dispatcher->dispatchTyped(new AnyLoginFailedEvent('ids-nobody', 'Wrong-Password-1'));
$loaded = array_values(array_diff($classes(), $before));
sort($loaded);

fwrite(STDOUT, "\n" . json_encode(['classes' => $loaded, 'queries' => $queries() - $queriesBefore], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
