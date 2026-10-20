<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Guard\AddressGuard;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs the request guards against synthetic addresses and prints the time
 * per request, with a cold and a warm cache, for PR descriptions and support.
 */
class Benchmark extends Base {
	public function __construct(
		private readonly AddressGuard $addressGuard,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:benchmark')
			->setDescription('Measure the cost of the request guards per request')
			->addOption('iterations', 'i', InputOption::VALUE_REQUIRED, 'Requests per measurement', '10000');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$iterations = max(100, min(1000000, (int)$input->getOption('iterations')));

		// Cold: a different documentation-range address every time, so every
		// verdict is resolved from the database.
		$cold = $this->measure($iterations, static fn (int $i): string => '198.51.' . intdiv($i, 256) % 256 . '.' . $i % 256);
		// Warm: the same address, so the verdict comes from the cache.
		$warm = $this->measure($iterations, static fn (int $i): string => '203.0.113.7');

		$result = [
			'iterations' => $iterations,
			'cold_us_per_request' => round($cold, 2),
			'warm_us_per_request' => round($warm, 2),
		];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $result);
			return self::SUCCESS;
		}
		$output->writeln(sprintf('Address guard, %d requests each:', $iterations));
		$output->writeln(sprintf('  cold cache (every address new): %.2f µs per request', $cold));
		$output->writeln(sprintf('  warm cache (same address):      %.2f µs per request', $warm));
		return self::SUCCESS;
	}

	/**
	 * @param \Closure(int): string $address
	 * @return float microseconds per request
	 */
	private function measure(int $iterations, \Closure $address): float {
		$start = hrtime(true);
		for ($i = 0; $i < $iterations; $i++) {
			$this->addressGuard->decisionFor($address($i));
		}
		return (hrtime(true) - $start) / 1000 / $iterations;
	}
}
