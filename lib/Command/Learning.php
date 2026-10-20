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
use OCA\IntrusionDetection\Learning\LearningService;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Learning extends Base {
	public function __construct(
		private readonly LearningService $learning,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:learning')
			->setDescription('Start, extend or end learning mode, in which checks only observe')
			->addOption('start', null, InputOption::VALUE_REQUIRED, 'Start learning mode for a number of days, e.g. 7d')
			->addOption('extend', null, InputOption::VALUE_REQUIRED, 'Add days to the learning period, e.g. 7d')
			->addOption('stop', null, InputOption::VALUE_NONE, 'End learning mode now; checks set to Protect start acting');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		try {
			if ($input->getOption('stop')) {
				$this->learning->stop('occ');
				$output->writeln('Learning mode ended. Checks set to Protect act now.');
				return self::SUCCESS;
			}
			if (is_string($input->getOption('start'))) {
				$until = $this->learning->start($this->days((string)$input->getOption('start')), 'occ');
				$output->writeln('Learning mode until ' . date('c', $until) . '.');
				return self::SUCCESS;
			}
			if (is_string($input->getOption('extend'))) {
				$until = $this->learning->extend($this->days((string)$input->getOption('extend')), 'occ');
				$output->writeln('Learning mode until ' . date('c', $until) . '.');
				return self::SUCCESS;
			}
		} catch (\InvalidArgumentException $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return self::INVALID;
		}
		$output->writeln($this->learning->isActive()
			? sprintf('Learning mode is on: %d day(s) left, until %s.', $this->learning->daysLeft(), date('c', $this->learning->until()))
			: 'Learning mode is off.');
		return self::SUCCESS;
	}

	private function days(string $raw): int {
		try {
			$seconds = ParamDefinition::parseDuration(preg_match('/^\d+$/', trim($raw)) ? trim($raw) . 'd' : $raw);
		} catch (InvalidParamException) {
			throw new \InvalidArgumentException('Give a number of days, e.g. 7d');
		}
		return max(1, intdiv($seconds, 86400));
	}
}
