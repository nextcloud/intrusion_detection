<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Db\Lockdown as LockdownEntry;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownException;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * occ intrusion:lockdown: start, extend, end and show lockdown mode
 * (concept section 17.1). It works whatever a lockdown blocks, so an
 * administrator who cannot confirm a login can always end one here.
 */
class Lockdown extends Base {
	public function __construct(
		private readonly LockdownService $lockdown,
		private readonly LockdownState $state,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:lockdown')
			->setDescription('Start, extend, end or show lockdown mode: extra confirmation for every password login and more, for 1 to 24 hours')
			->addOption('start', null, InputOption::VALUE_REQUIRED, 'Start a lockdown for this long, e.g. 6h')
			->addOption('reason', null, InputOption::VALUE_REQUIRED, 'Why, for the other administrators and the audit log', '')
			->addOption('effects', null, InputOption::VALUE_REQUIRED, 'With --start: the effects to switch on, comma-separated (' . implode(', ', LockdownEffect::values()) . ')')
			->addOption('extend', null, InputOption::VALUE_REQUIRED, 'Extend the running lockdown by this long, e.g. 2h (at most 24 hours from now)')
			->addOption('end', null, InputOption::VALUE_NONE, 'End the running lockdown now')
			->addOption('status', null, InputOption::VALUE_NONE, 'Show whether a lockdown is running (the default)');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		try {
			if ($input->getOption('end')) {
				$output->writeln($this->lockdown->end(LockdownEntry::ACTOR_OCC) ? 'Lockdown ended.' : 'No lockdown is running.');
				return self::SUCCESS;
			}
			if (is_string($input->getOption('start'))) {
				$effects = is_string($input->getOption('effects')) ? array_values(array_filter(array_map('trim', explode(',', (string)$input->getOption('effects'))))) : null;
				$started = $this->lockdown->start($this->seconds((string)$input->getOption('start')), (string)$input->getOption('reason'), LockdownEntry::ACTOR_OCC, $effects);
				$output->writeln('Lockdown until ' . date('c', $started->getPlannedEnd()) . '.');
				return self::SUCCESS;
			}
			if (is_string($input->getOption('extend'))) {
				$until = $this->lockdown->extend($this->seconds((string)$input->getOption('extend')), LockdownEntry::ACTOR_OCC);
				$output->writeln('Lockdown until ' . date('c', $until) . '.');
				return self::SUCCESS;
			}
		} catch (\InvalidArgumentException|LockdownException $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return self::INVALID;
		} catch (InvalidParamException $e) {
			$output->writeln('<error>Unknown effect. Use: ' . implode(', ', LockdownEffect::values()) . '</error>');
			return self::INVALID;
		}
		$info = $this->state->info();
		if (!$info['active']) {
			$output->writeln('No lockdown is running.');
			return self::SUCCESS;
		}
		$output->writeln(sprintf('Lockdown until %s, started by %s at %s.', date('c', $info['until']), $info['startedBy'], date('c', $info['startedAt'])));
		if ($info['reason'] !== '') {
			$output->writeln('Reason: ' . $info['reason']);
		}
		$output->writeln('Effects: ' . ($info['effects'] === [] ? 'none' : implode(', ', $info['effects'])));
		return self::SUCCESS;
	}

	private function seconds(string $raw): int {
		try {
			$seconds = ParamDefinition::parseDuration(preg_match('/^\d+$/', trim($raw)) ? trim($raw) . 'h' : $raw);
		} catch (InvalidParamException) {
			throw new \InvalidArgumentException('Give a duration such as 6h or 90m');
		}
		if ($seconds < LockdownEffect::MIN_DURATION || $seconds > LockdownEffect::MAX_DURATION) {
			throw new \InvalidArgumentException('A lockdown lasts, and is extended by, 1 to 24 hours');
		}
		return $seconds;
	}
}
