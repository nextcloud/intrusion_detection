<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Export\FirewallExporter;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Status extends Base {
	public function __construct(
		private readonly AppSettings $appSettings,
		private readonly CheckSettings $settings,
		private readonly CheckRegistry $registry,
		private readonly LearningService $learning,
		private readonly Prerequisites $prerequisites,
		private readonly Caches $caches,
		private readonly BanMapper $bans,
		private readonly DetectionTotals $totals,
		private readonly GuardTimer $timer,
		private readonly ITimeFactory $timeFactory,
		private readonly FirewallExporter $exporter,
		private readonly BlocklistOverview $blocklists,
		private readonly IConfig $config,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:status')
			->setDescription('Show what intrusion detection is doing: mode, learning period, prerequisites, cost and counts');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$now = $this->timeFactory->getTime();
		$modes = ['off' => 0, 'observe' => 0, 'protect' => 0];
		foreach ($this->registry->configurable() as $check) {
			$modes[$this->settings->effectiveMode($check->id)->value]++;
		}
		$last24h = $this->totals->perCheck($now - 86400);
		$timing = $this->timer->summary();
		$export = $this->exporter->status()->toArray();
		$lists = array_values(array_filter($this->blocklists->lists(), static fn (array $l): bool => $l['enabled']));

		$status = [
			'state' => !$this->appSettings->isEnabled() ? 'off' : ($this->learning->isActive() ? 'learning' : 'protecting'),
			'learning_until' => $this->learning->until() > $now ? date('c', $this->learning->until()) : null,
			'learning_days_left' => $this->learning->daysLeft(),
			'checks' => $modes,
			'memory_cache' => $this->caches->kind(),
			'mail' => $this->prerequisites->hasMail(),
			'active_bans' => $this->bans->countActive($now),
			'detections_24h' => array_sum(array_map(static fn (array $c): int => $c['enforced'] + $c['observed'], $last24h)),
			'guard_average_us' => $timing === null ? null : round($timing['averageMicroseconds'], 1),
			'guard_max_us' => $timing['maxMicroseconds'] ?? null,
			'guard_samples' => $timing['samples'] ?? 0,
			'export' => $export,
			'blocklists_enabled' => count($lists),
			'blocklists_stale' => count(array_filter($lists, static fn (array $l): bool => $l['stale'])),
			'locked' => $this->appSettings->isLocked(),
			'guards' => $this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false) ? 'off' : 'on',
		];

		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $status);
			return self::SUCCESS;
		}

		$output->writeln(match ($status['state']) {
			'off' => '<comment>Off.</comment> No checks run.',
			'learning' => sprintf('<info>Learning:</info> %d day(s) left, until %s. Checks set to Protect only observe.', $status['learning_days_left'], $status['learning_until']),
			default => '<info>Protecting.</info>',
		});
		if ($status['guards'] === 'off') {
			$output->writeln('<error>Request guards off:</error> "intrusion_detection.disable_guards" is set in config.php, so no request is checked for blocks, blocklists, trap URLs, injection probes or stolen credentials.');
		}
		if ($status['locked']) {
			$output->writeln('<info>Locked in config.php:</info> intrusion detection, the admin change alerts and the approval of new administrators cannot be switched off.');
		}
		$output->writeln(sprintf('Checks: %d protecting, %d observing, %d off.', $modes[Mode::Protect->value], $modes[Mode::Observe->value], $modes[Mode::Off->value]));
		$output->writeln(sprintf('Memory cache: %s. Mail: %s.', $status['memory_cache'], $status['mail'] ? 'configured' : 'not configured'));
		$output->writeln(sprintf('Active blocks: %d. Detections in the last 24 hours: %d.', $status['active_bans'], $status['detections_24h']));
		$output->writeln(match (true) {
			!$export['active'] => 'Firewall export: off.',
			$export['error'] !== null => sprintf('Firewall export: <error>%s</error> (%s).', $export['error'], (string)$export['directory']),
			default => sprintf('Firewall export: %s to %s, last written %s.', implode(', ', $export['files']), (string)$export['directory'], $export['lastWriteAt'] === null ? 'never' : date('c', $export['lastWriteAt'])),
		});
		$output->writeln(sprintf('Blocklists: %d enabled, %d not downloaded for more than three intervals.', $status['blocklists_enabled'], $status['blocklists_stale']));
		$output->writeln($timing === null
			? 'Cost per request: not measured yet (needs a memory cache; 1 in 1000 requests is measured).'
			: sprintf('Cost per request: %.1f µs on average, %d µs at most (%d samples, last 24 hours).', $timing['averageMicroseconds'], $timing['maxMicroseconds'], $timing['samples']));
		return self::SUCCESS;
	}
}
