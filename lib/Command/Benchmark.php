<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\AppFramework\Http\Request;
use OC\Core\Command\Base;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\FreshRequestProbe;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICache;
use OCP\ICacheFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IRequestId;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs every request guard of the app against synthetic WebDAV requests
 * that log in with Basic credentials, and prints the time per request for
 * each guard and in total, with a cold and a warm cache, for PR
 * descriptions and support.
 *
 * - Cold: every request comes from a new address with a new app password,
 *   so every address verdict is resolved from the database and every
 *   credential is looked up in vain (it is only written once it logged in,
 *   which the synthetic requests do not).
 * - Warm: the same address and an app password the check knows: the common
 *   case.
 *
 * The credential check tracks the synthetic app passwords in a cache of its
 * own, emptied afterwards, so the real entries are not touched.
 *
 * Both run in this process, where every class is loaded and every service
 * built after the first request. The fresh-process figure is what a new web
 * server process pays: the median of FRESH_RUNS new PHP processes that each
 * read a setting and run the guards once ({@see FreshRequestProbe}).
 *
 * @psalm-import-type FreshRequestResult from FreshRequestProbe
 */
class Benchmark extends Base {
	private const GUARDS = ['address', 'trap_url', 'injection_probe', 'credential_use'];
	private const WARM_ADDRESS = '203.0.113.7';
	public const FRESH_RUNS = 5;

	public function __construct(
		private readonly AddressGuard $addressGuard,
		private readonly TrapUrlGuard $trapUrlGuard,
		private readonly PayloadGuard $payloadGuard,
		private readonly CredentialUseGuard $credentialGuard,
		private readonly CredentialTracker $tracker,
		private readonly ICacheFactory $cacheFactory,
		private readonly Prerequisites $prerequisites,
		private readonly Fingerprinter $fingerprinter,
		private readonly ITimeFactory $timeFactory,
		private readonly IConfig $config,
		private readonly IRequestId $requestId,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:benchmark')
			->setDescription('Measure the cost of the request guards per request')
			->addOption('iterations', 'i', InputOption::VALUE_REQUIRED, 'Requests per measurement', '10000')
			->addOption('no-fresh', null, InputOption::VALUE_NONE, 'Skip the measurement in new PHP processes');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$iterations = max(100, min(1000000, (int)$input->getOption('iterations')));
		[$cache, $cacheKind] = $this->benchmarkCache();
		$tracker = $cache === null ? null : $this->tracker->withCache($cache);
		$guards = $this->guards($tracker);
		try {
			$cold = [];
			$requests = [];
			for ($i = 0; $i < $iterations; $i++) {
				$requests[] = $this->request('198.51.' . intdiv($i, 256) % 256 . '.' . $i % 256, bin2hex(random_bytes(36)));
			}
			foreach ($guards as $name => $guard) {
				$cold[$name] = $this->measure($guard, $requests);
			}

			$warm = [];
			$appPassword = bin2hex(random_bytes(36));
			$request = $this->request(self::WARM_ADDRESS, $appPassword);
			// The app password logged in before, so the check knows it.
			$credential = PresentedCredential::fromRequest($request, '');
			if ($tracker !== null && $credential !== null) {
				$tracker->track($this->fingerprinter->credential($credential->keyMaterial()), SourceKey::fromIp(self::WARM_ADDRESS), $credential->userTag(), $this->timeFactory->getTime());
			}
			$requests = array_fill(0, $iterations, $request);
			foreach ($guards as $name => $guard) {
				$guard($request);
				$warm[$name] = $this->measure($guard, $requests);
			}
		} finally {
			$cache?->clear();
		}

		$fresh = $input->getOption('no-fresh') ? null : $this->fresh();
		$result = [
			'iterations' => $iterations,
			'credential_cache' => $cacheKind,
			'guards' => [],
			'total' => ['cold_us_per_request' => round(array_sum($cold), 2), 'warm_us_per_request' => round(array_sum($warm), 2)],
		];
		foreach (self::GUARDS as $name) {
			$result['guards'][$name] = ['cold_us_per_request' => round($cold[$name], 2), 'warm_us_per_request' => round($warm[$name], 2)];
		}
		if ($fresh !== null) {
			$result['fresh_process'] = [
				'runs' => self::FRESH_RUNS,
				'settings_us' => $fresh['settings_us'],
				'guards_us' => $fresh['guards_us'],
				'total_us' => $fresh['total_us'],
				'queries' => $fresh['queries'],
				'app_classes' => $fresh['app_classes'],
			];
		}
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $result);
			return self::SUCCESS;
		}
		$output->writeln(sprintf('Request guards, %d WebDAV requests with Basic credentials each, µs per request:', $iterations));
		$output->writeln(sprintf('  %-18s %10s %10s', '', 'cold', 'warm'));
		foreach (self::GUARDS as $name) {
			$output->writeln(sprintf('  %-18s %10.2f %10.2f', $name, $cold[$name], $warm[$name]));
		}
		$output->writeln(sprintf('  %-18s %10.2f %10.2f', 'total', array_sum($cold), array_sum($warm)));
		$output->writeln(match ($cacheKind) {
			'distributed' => 'The credential check used the distributed cache.',
			'local' => 'The credential check used a local cache such as APCu: each web server sees only its own requests.',
			default => 'No memory cache: the credential check is unavailable and returned at once.',
		});
		$output->writeln('Cold: a new address and an unknown app password per request. Warm: the same address and a known app password every time.');
		if ($fresh !== null) {
			$output->writeln(sprintf(
				'Fresh process (median of %d new PHP processes): %.1f µs per request, of which %.1f µs for the first settings read and %.1f µs for the guards; %d queries, %d classes of the app loaded.',
				self::FRESH_RUNS,
				$fresh['total_us'],
				$fresh['settings_us'],
				$fresh['guards_us'],
				$fresh['queries'],
				$fresh['app_classes'],
			));
		} elseif (!$input->getOption('no-fresh')) {
			$output->writeln('Fresh process: the measurement in a new PHP process failed.');
		}
		return self::SUCCESS;
	}

	/**
	 * The median of FRESH_RUNS runs in new PHP processes, by total time.
	 *
	 * @return FreshRequestResult|null null when a process failed
	 */
	private function fresh(): ?array {
		$runs = [];
		for ($i = 0; $i < self::FRESH_RUNS; $i++) {
			$run = FreshRequestProbe::inNewProcess();
			if ($run === null) {
				return null;
			}
			$runs[] = $run;
		}
		usort($runs, static fn (array $a, array $b): int => $a['total_us'] <=> $b['total_us']);
		return $runs[intdiv(count($runs), 2)];
	}

	/**
	 * @return array<string, \Closure(IRequest): mixed> in the order core runs them
	 */
	private function guards(?CredentialTracker $tracker): array {
		$credentialGuard = $tracker === null ? $this->credentialGuard : $this->credentialGuard->withTracker($tracker);
		return [
			// The address guard's own entry point, so that the measured
			// requests do not count in the guard timer of the admin page.
			'address' => fn (IRequest $request): mixed => $this->addressGuard->decisionFor($request->getRemoteAddress()),
			'trap_url' => fn (IRequest $request): mixed => $this->trapUrlGuard->check($request),
			'injection_probe' => fn (IRequest $request): mixed => $this->payloadGuard->check($request),
			'credential_use' => fn (IRequest $request): mixed => $credentialGuard->check($request),
		];
	}

	/**
	 * @return array{0: ?ICache, 1: 'distributed'|'local'|'none'}
	 */
	private function benchmarkCache(): array {
		$prefix = Application::APP_ID . '-benchmark';
		if (!$this->prerequisites->hasMemoryCache()) {
			return [null, 'none'];
		}
		// The same cache the check uses; core hands out the local one as
		// the distributed cache when no distributed cache is configured.
		$cache = $this->cacheFactory->isAvailable() ? $this->cacheFactory->createDistributed($prefix) : $this->cacheFactory->createLocal($prefix);
		return [$cache, $this->prerequisites->hasDistributedCache() ? 'distributed' : 'local'];
	}

	private function request(string $address, string $appPassword): IRequest {
		return new Request([
			'server' => [
				'REQUEST_URI' => '/remote.php/dav/files/alice/Documents/',
				'SCRIPT_NAME' => '/remote.php',
				'REQUEST_METHOD' => 'PROPFIND',
				'REMOTE_ADDR' => $address,
				'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('alice:' . $appPassword),
				'PHP_AUTH_USER' => 'alice',
				'PHP_AUTH_PW' => $appPassword,
				'HTTP_USER_AGENT' => 'Mozilla/5.0 (Linux) mirall/3.15.0 (Nextcloud)',
			],
		], $this->requestId, $this->config);
	}

	/**
	 * @param \Closure(IRequest): mixed $guard
	 * @param list<IRequest> $requests
	 * @return float microseconds per request
	 */
	private function measure(\Closure $guard, array $requests): float {
		$start = hrtime(true);
		foreach ($requests as $request) {
			$guard($request);
		}
		return (hrtime(true) - $start) / 1000 / count($requests);
	}
}
