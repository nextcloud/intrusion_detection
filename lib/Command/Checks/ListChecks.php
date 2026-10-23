<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Checks;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\IL10N;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ListChecks extends Base {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly CheckSettings $settings,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:checks:list')
			->setDescription('List the checks with their mode and responses')
			->addOption('internal', null, InputOption::VALUE_NONE, 'Include the checks the app raises itself');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$checks = $input->getOption('internal') ? $this->registry->all() : $this->registry->configurable();
		$rows = [];
		foreach ($checks as $check) {
			$state = $this->settings->modeState($check->id);
			$rows[] = [
				'id' => $check->id,
				'name' => $check->texts($this->l)->name,
				'mode' => $state->configured->value,
				'runs_as' => $state->effective->value . ($state->reason !== null ? ' (' . $state->reason . ')' : ''),
				'responses' => implode(', ', array_map(static fn (ResponseType $r): string => $r->value, $this->settings->responses($check->id))),
			];
		}
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $rows);
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Check', 'Name', 'Mode', 'Runs as', 'Responses']);
		$table->setRows(array_map('array_values', $rows));
		$table->render();
		return self::SUCCESS;
	}
}
