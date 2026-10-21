<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Http\Request;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IRequestId;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The per-request budget of the credential check (concept section 19.1):
 * one HMAC and one cache get on the common path (warm: an app password the
 * check knows), and on the path of credentials it does not know yet (cold:
 * they are only written once they logged in). Measured with in-memory
 * stand-ins for APCu (values kept as they are) and for a distributed cache
 * (values serialised, as Redis and Memcached store them); the network
 * round trip of a real distributed cache comes on top.
 */
#[Group('DB')]
class CredentialUseBenchmarkTest extends IntegrationTestCase {
	private const REQUESTS = 10000;
	/** The whole guard budget is 100 µs; this check may take a small part of it */
	private const BUDGET_US = 20;

	private CredentialTracker $tracker;

	public function testTheCommonPathStaysWithinBudget(): void {
		$results = [];
		foreach (['local' => new ArrayCache(), 'distributed' => new SerialisingCache()] as $kind => $cache) {
			$guard = $this->guard($cache, $kind === 'distributed');
			$warmRequest = $this->request('198.51.100.7', 'AbCdE-FgHiJ-KlMnO-PqRsT-UvWxY');
			$warm = array_fill(0, self::REQUESTS, $warmRequest);
			$cold = [];
			for ($i = 0; $i < self::REQUESTS; $i++) {
				$cold[] = $this->request('198.51.' . intdiv($i, 250) % 250 . '.' . ($i % 250 + 1), bin2hex(random_bytes(36)));
			}
			// The warm app password logged in before: the check knows it.
			$credential = PresentedCredential::fromRequest($warmRequest, '');
			$this->assertNotNull($credential);
			$this->tracker->track(Server::get(Fingerprinter::class)->credential($credential->keyMaterial()), SourceKey::fromIp('198.51.100.7'), $credential->userTag(), time());
			$guard->check($warmRequest);
			$this->assertSame(1, count((new \ReflectionProperty($cache, 'cachedData'))->getValue($cache)), 'Only the known app password has an entry');
			$results[$kind] = ['warm' => $this->measure($guard, $warm), 'cold' => $this->measure($guard, $cold)];
			$this->assertSame(1, count((new \ReflectionProperty($cache, 'cachedData'))->getValue($cache)), 'Unknown credentials are not written');
		}
		fwrite(STDERR, sprintf(
			"\n[token_concurrent_use] guard per request with Basic credentials, %d requests: APCu-like local cache %.2f µs warm, %.2f µs cold; distributed-like cache %.2f µs warm, %.2f µs cold (without the network round trip)\n",
			self::REQUESTS,
			$results['local']['warm'],
			$results['local']['cold'],
			$results['distributed']['warm'],
			$results['distributed']['cold'],
		));
		foreach ($results as $kind => $result) {
			$this->assertLessThan(self::BUDGET_US, $result['warm'], $kind . ', common path');
		}
		$this->assertSame([], $this->db->getQueryBuilder()->select('id')->from('ids_detections')->executeQuery()->fetchAll(), 'Nothing is recorded');
	}

	private function guard(ICache $cache, bool $distributed): CredentialUseGuard {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn($distributed);
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->method('createLocal')->willReturn($cache);
		$factory->method('createDistributed')->willReturn($cache);
		$settings = new Settings(
			Server::get(IAppConfig::class),
			Server::get(CheckRegistry::class),
			Server::get(ITimeFactory::class),
			new Prerequisites($factory, Server::get(IConfig::class)),
			Server::get(GlobalSettings::class),
			Server::get(IEventDispatcher::class),
		);
		return new CredentialUseGuard(
			Server::get(IConfig::class),
			$settings,
			Server::get(Fingerprinter::class),
			$this->tracker = new CredentialTracker($factory, $settings),
			$this->addressGuardRan(),
			Server::get(ITimeFactory::class),
			Server::get(ContainerInterface::class),
			Server::get(LoggerInterface::class),
			Server::get(GuardTimer::class),
		);
	}

	/**
	 * The context as the address guard, which runs first, leaves it.
	 */
	private function addressGuardRan(): RequestContext {
		$context = new RequestContext();
		$context->setVerdict(new Verdict());
		return $context;
	}

	private function request(string $ip, string $appPassword): IRequest {
		// The real configuration: a mock would add its own cost to every request.
		return new Request([
			'server' => [
				'REQUEST_URI' => '/remote.php/dav/files/alice/',
				'SCRIPT_NAME' => '/remote.php',
				'REQUEST_METHOD' => 'PROPFIND',
				'REMOTE_ADDR' => $ip,
				'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('alice:' . $appPassword),
				'PHP_AUTH_USER' => 'alice',
				'PHP_AUTH_PW' => $appPassword,
			],
		], $this->createMock(IRequestId::class), Server::get(IConfig::class));
	}

	/**
	 * @param list<IRequest> $requests
	 * @return float µs per request
	 */
	private function measure(CredentialUseGuard $guard, array $requests): float {
		$start = hrtime(true);
		foreach ($requests as $request) {
			$guard->check($request);
		}
		return (hrtime(true) - $start) / 1000 / count($requests);
	}
}

/**
 * Stores values serialised, as a distributed cache does.
 */
class SerialisingCache extends ArrayCache {
	#[\Override]
	public function get($key) {
		$value = parent::get($key);
		return is_string($value) ? unserialize($value) : null;
	}

	#[\Override]
	public function set($key, $value, $ttl = 0) {
		return parent::set($key, serialize($value), $ttl);
	}
}
