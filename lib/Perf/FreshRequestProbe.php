<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Perf;

use OC\AppFramework\Http\Request;
use OC\DB\Connection;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IRequest;
use OCP\IRequestId;
use OCP\Server;

/**
 * What the app costs a plain request in a new PHP process, where nothing of
 * it is loaded yet: the first settings read (which makes core load the config
 * lexicon) and one pass of the request guards over a WebDAV request with an
 * app password, which is what every web server process pays per request.
 *
 * {@see run()} runs in a child process that occ intrusion:benchmark starts
 * with `php -r`; it prints one JSON object and nothing else.
 *
 * @psalm-type FreshRequestResult = array{settings_us: float, guards_us: float, total_us: float, queries: int, app_classes: int, classes: list<string>}
 */
final class FreshRequestProbe {
	public const ADDRESS = '203.0.113.7';
	private const APP_NAMESPACE = 'OCA\\IntrusionDetection\\';

	/**
	 * The code for `php -r` that runs the probe in a new process of this server.
	 */
	public static function code(string $serverRoot): string {
		return 'require ' . var_export($serverRoot . '/lib/base.php', true) . '; \\' . self::class . '::run();';
	}

	/**
	 * Measure and print the result as JSON on stdout.
	 */
	public static function run(): void {
		// Core reads its own app config on every request before the guards run.
		Server::get(IAppConfig::class)->getValueString('core', 'vendor', '');
		$request = self::request();
		$classesBefore = self::appClasses();
		$queriesBefore = self::queries();

		$start = hrtime(true);
		Server::get(Settings::class)->isEnabled();
		$settingsDone = hrtime(true);
		foreach ([AddressGuard::class, TrapUrlGuard::class, PayloadGuard::class, CredentialUseGuard::class] as $class) {
			Server::get($class)->check($request);
		}
		$end = hrtime(true);

		$classes = array_values(array_diff(self::appClasses(), $classesBefore));
		sort($classes);
		$result = [
			'settings_us' => round(($settingsDone - $start) / 1000, 1),
			'guards_us' => round(($end - $settingsDone) / 1000, 1),
			'total_us' => round(($end - $start) / 1000, 1),
			'queries' => self::queries() - $queriesBefore,
			'app_classes' => count($classes),
			'classes' => $classes,
		];
		fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
	}

	/**
	 * The directory of this server's lib/base.php.
	 */
	public static function serverRoot(): string {
		return dirname((string)(new \ReflectionClass(\OC\Server::class))->getFileName(), 3);
	}

	/**
	 * Run the probe in a new PHP process of this server.
	 *
	 * @return FreshRequestResult|null null when the process failed
	 */
	public static function inNewProcess(int $timeout = 60): ?array {
		$process = proc_open([PHP_BINARY, '-r', self::code(self::serverRoot())], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		if (!is_resource($process)) {
			return null;
		}
		stream_set_timeout($pipes[1], $timeout);
		$output = stream_get_contents($pipes[1]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		if (proc_close($process) !== 0 || !is_string($output)) {
			return null;
		}
		$start = strrpos($output, '{"settings_us"');
		$decoded = $start === false ? null : json_decode(substr($output, $start), true);
		if (!is_array($decoded) || !isset($decoded['total_us'], $decoded['classes']) || !is_array($decoded['classes'])) {
			return null;
		}
		return [
			'settings_us' => (float)$decoded['settings_us'],
			'guards_us' => (float)$decoded['guards_us'],
			'total_us' => (float)$decoded['total_us'],
			'queries' => (int)$decoded['queries'],
			'app_classes' => (int)$decoded['app_classes'],
			'classes' => array_values(array_filter($decoded['classes'], 'is_string')),
		];
	}

	private static function request(): IRequest {
		$appPassword = 'aaaaa-bbbbb-ccccc-ddddd-eeeee';
		return new Request([
			'server' => [
				'REQUEST_URI' => '/remote.php/dav/files/alice/Documents/',
				'SCRIPT_NAME' => '/remote.php',
				'REQUEST_METHOD' => 'PROPFIND',
				'REMOTE_ADDR' => self::ADDRESS,
				'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('alice:' . $appPassword),
				'PHP_AUTH_USER' => 'alice',
				'PHP_AUTH_PW' => $appPassword,
				'HTTP_USER_AGENT' => 'Mozilla/5.0 (Linux) mirall/3.15.0 (Nextcloud)',
			],
		], Server::get(IRequestId::class), Server::get(IConfig::class));
	}

	/**
	 * @return list<string>
	 */
	private static function appClasses(): array {
		return array_values(array_filter(
			array_merge(get_declared_classes(), get_declared_interfaces(), get_declared_traits()),
			static fn (string $class): bool => str_starts_with($class, self::APP_NAMESPACE),
		));
	}

	private static function queries(): int {
		$db = Server::get(IDBConnection::class);
		$inner = method_exists($db, 'getInner') ? $db->getInner() : null;
		return $inner instanceof Connection ? (int)$inner->getStats()['executed'] : 0;
	}
}
