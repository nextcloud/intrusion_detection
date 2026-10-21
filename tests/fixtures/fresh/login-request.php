<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Run by FreshRequestCostTest in a new PHP process: what the app loads and
 * queries for a WebDAV request with an app password, step by step. Prints
 * one JSON object.
 *
 * Usage: php login-request.php <server root> <uid>
 */

use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Listener\SabrePluginAddListener;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\IDBConnection;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;

[, $root, $uid] = $argv;
$appPassword = 'aaaaa-bbbbb-ccccc-ddddd-eeeee';
$_SERVER['PHP_AUTH_USER'] = $uid;
$_SERVER['PHP_AUTH_PW'] = $appPassword;
$_SERVER['HTTP_AUTHORIZATION'] = 'Basic ' . base64_encode($uid . ':' . $appPassword);
$_SERVER['REMOTE_ADDR'] = '203.0.113.71';

require $root . '/lib/base.php';

$classes = static fn (): array => array_values(array_filter(
	array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits()),
	static fn (string $class): bool => str_starts_with($class, 'OCA\\IntrusionDetection\\'),
));
$queries = static fn (): int => (int)Server::get(IDBConnection::class)->getInner()->getStats()['executed'];
$step = static function (callable $work) use ($classes, $queries): array {
	$before = $classes();
	$queriesBefore = $queries();
	$work();
	$loaded = array_values(array_diff($classes(), $before));
	sort($loaded);
	return ['classes' => $loaded, 'queries' => $queries() - $queriesBefore];
};

$result = ['afterBoot' => $classes()];
Server::get(IAppConfig::class)->getValueString('core', 'vendor', '');
$result['lexicon'] = $step(static fn () => (new Lexicon())->getAppConfigs());

$user = Server::get(IUserManager::class)->get($uid);
$event = new UserLoggedInEvent($user, $uid, null, true);
$dispatcher = Server::get(IEventDispatcher::class);
$result['firstLogin'] = $step(static fn () => $dispatcher->dispatchTyped($event));
$result['repeatedLogin'] = $step(static fn () => Server::get(LoginListener::class)->handle($event));

Server::get(IUserSession::class)->setUser($user);
$server = new \Sabre\DAV\Server();
$result['davPlugin'] = $step(static function () use ($server): void {
	Server::get(SabrePluginAddListener::class)->handle(new \OCA\DAV\Events\SabrePluginAddEvent($server));
	$server->getPlugin('intrusion-detection-session-state');
	Server::get(SessionStatePlugin::class)->beforeMethod(new \Sabre\HTTP\Request('PROPFIND', '/remote.php/dav/files/' . $uid . '/'), new \Sabre\HTTP\Response());
});

fwrite(STDOUT, "\n" . json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
