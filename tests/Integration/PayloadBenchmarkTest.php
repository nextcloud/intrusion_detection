<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Http\Request;
use OCA\IntrusionDetection\Check\Payload\PayloadInspector;
use OCA\IntrusionDetection\Check\Payload\PayloadSettings;
use OCA\IntrusionDetection\Check\Payload\PreFilter;
use OCA\IntrusionDetection\Check\Payload\RequestParts;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCP\IConfig;
use OCP\IRequestId;
use OCP\Route\IRouter;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The performance budget of the injection probe check (section 19.1 of the
 * concept), measured on URLs generated from the router's real routes.
 */
#[Group('DB')]
class PayloadBenchmarkTest extends IntegrationTestCase {
	private const URLS = 10000;
	/** Budget for all URLs together */
	private const BUDGET_MS = 50;
	/** Budget for inspecting 8 KB in full; the concept's target is 0.2 ms */
	private const FULL_INSPECTION_BUDGET_MS = 1.0;

	private const QUERIES = [
		'',
		'?format=json',
		'?fileId=12345&x=32&y=32&a=1',
		'?v=3',
		'?redirect_url=%2Fapps%2Ffiles%2F',
		'?limit=50&offset=0',
		'?dir=/Documents/Projects&openfile=true',
		'?search=quarterly+report&limit=5',
		'?format=json&lastKnownMessageId=12345&limit=100&includeLastKnown=0',
		'?requesttoken=Z3V0ZW4gVGFnIGRhcyBpc3QgZWluIFRva2Vu%3AbW9yZSByYW5kb20gYnl0ZXMgaGVyZQ%3D%3D',
	];

	public function testTypicalUrlsFromTheRoutesPassQuickly(): void {
		$requests = $this->typicalRequests();
		$this->assertCount(self::URLS, $requests);
		$guard = Server::get(PayloadGuard::class);

		$flagged = 0;
		foreach ($requests as [$request, $parts]) {
			$flagged += PreFilter::hit($parts) ? 1 : 0;
		}

		$decisions = [];
		$start = hrtime(true);
		foreach ($requests as [$request]) {
			$decisions[] = $guard->check($request);
		}
		$ms = (hrtime(true) - $start) / 1e6;
		$this->assertSame([], array_filter($decisions), 'No typical request is refused');
		$this->assertSame([], $this->db->getQueryBuilder()->select('id')->from('ids_detections')->executeQuery()->fetchAll(), 'None is recorded');

		$start = hrtime(true);
		foreach ($requests as [, $parts]) {
			PreFilter::hit($parts);
		}
		$preFilterUs = (hrtime(true) - $start) / 1000 / self::URLS;

		fwrite(STDERR, sprintf(
			"\n[injection_probe] %d URLs from %d routes through the guard: %.1f ms in total (%.2f µs each); pre-filter alone %.2f µs each; %d (%.1f %%) inspected in full\n",
			self::URLS,
			count($this->routePaths()),
			$ms,
			$ms * 1000 / self::URLS,
			$preFilterUs,
			$flagged,
			100 * $flagged / self::URLS,
		));
		$this->assertLessThan(self::BUDGET_MS, $ms);
		$this->assertLessThan(5, $preFilterUs, 'The pre-filter target is under 5 µs');
	}

	public function testFullInspectionOf8KbStaysWithinBudget(): void {
		$inspector = Server::get(PayloadInspector::class);
		$rules = Server::get(PayloadSettings::class)->rules();
		$benign = '/index.php/apps/foo?note=' . substr(str_repeat("it's+a+quote,+isn't+it?+", 400), 0, 8100);
		$attack = '/index.php/apps/foo?a=' . str_repeat('x', 7000) . '&id=1%27%20UNION%20SELECT%20password%20FROM%20oc_users--&p=' . str_repeat('QUJD', 250);
		foreach (['benign text with quotes' => $benign, 'attack' => $attack] as $name => $uri) {
			$parts = RequestParts::fromUri($uri, '/index.php');
			$inspector->inspect($parts, $rules);
			$runs = 200;
			$start = hrtime(true);
			for ($i = 0; $i < $runs; $i++) {
				$inspector->inspect($parts, $rules);
			}
			$ms = (hrtime(true) - $start) / 1e6 / $runs;
			fwrite(STDERR, sprintf("[injection_probe] full inspection of 8 KB (%s): %.3f ms\n", $name, $ms));
			$this->assertLessThan(self::FULL_INSPECTION_BUDGET_MS, $ms, $name);
		}
	}

	/**
	 * @return list<array{0: Request, 1: RequestParts}>
	 */
	private function typicalRequests(): array {
		$paths = $this->routePaths();
		$paths[] = '/remote.php/dav/files/alice/Documents/Photo%202024%20(1).jpg';
		$paths[] = '/remote.php/dav/files/alice/Bob\'s%20notes.md';
		$paths[] = '/public.php/dav/files/AbCdEfGhIjKlMnO/';
		$paths[] = '/status.php';
		// The real configuration: a mock would add its own cost to every request.
		$config = Server::get(IConfig::class);
		$cookie = $config->getSystemValueString('instanceid');

		$requests = [];
		for ($i = 0; count($requests) < self::URLS; $i++) {
			$path = $paths[$i % count($paths)];
			$uri = $path . self::QUERIES[intdiv($i, count($paths)) % count(self::QUERIES)];
			$script = self::script($path);
			$request = new Request([
				'server' => [
					'REQUEST_URI' => $uri,
					'SCRIPT_NAME' => $script,
					'REMOTE_ADDR' => '198.51.100.' . ($i % 250 + 1),
					'REQUEST_METHOD' => 'GET',
					'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0',
				],
				'cookies' => $i % 2 === 0 ? [$cookie => 'abc'] : [],
			], $this->createMock(IRequestId::class), $config);
			$requests[] = [$request, RequestParts::fromUri($uri, $script)];
		}
		return $requests;
	}

	/**
	 * The path of every route, with typical values for its parameters.
	 *
	 * @return list<string>
	 */
	private function routePaths(): array {
		/** @var \OC\Route\Router $router */
		$router = Server::get(IRouter::class);
		\OC_App::loadApps();
		$router->loadRoutes();
		$paths = [];
		foreach ($router->getRouteCollection()->all() as $route) {
			$path = (string)preg_replace_callback('/\{([^}]+)\}/', static fn (array $m): string => self::typicalValue($m[1]), $route->getPath());
			$paths[] = str_starts_with($path, '/ocsapp/') ? '/ocs/v2.php' . substr($path, 7) : '/index.php' . $path;
		}
		$paths = array_values(array_unique($paths));
		$this->assertGreaterThan(200, count($paths), 'The router has the routes of the enabled apps');
		return $paths;
	}

	private static function typicalValue(string $name): string {
		$lower = strtolower($name);
		return match (true) {
			str_contains($lower, 'token') => 'AbCdEfGhIjKlMnO',
			in_array($lower, ['user', 'userid', 'uid', 'targetuserid', 'username'], true) => 'alice',
			in_array($lower, ['x', 'y', 'size', 'width', 'height'], true) => '64',
			in_array($lower, ['path', 'file', 'filename', 'dir', 'filepath'], true) => 'Documents/Quarterly%20report.pdf',
			str_contains($lower, 'app') => 'files',
			str_contains($lower, 'group') => 'staff',
			$lower === 'id' || str_ends_with($lower, 'id') => '12345',
			in_array($lower, ['type', 'format'], true) => 'json',
			default => 'abc123',
		};
	}

	private static function script(string $path): string {
		foreach (['/remote.php', '/public.php', '/status.php', '/ocs/v2.php'] as $script) {
			if (str_starts_with($path, $script)) {
				return $script;
			}
		}
		return '/index.php';
	}
}
