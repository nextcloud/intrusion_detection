<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Checks;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Change a check, with exactly the validation the admin page uses. Nothing
 * is saved unless every given value is valid.
 */
class Set extends Base {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly SettingsEditor $settings,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:checks:set')
			->setDescription('Change the mode, responses or settings of a check')
			->addArgument('check', InputArgument::REQUIRED, 'The check id, see intrusion:checks:list')
			->addOption('mode', null, InputOption::VALUE_REQUIRED, 'off, observe or protect')
			->addOption('param', 'p', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'A setting as name=value; durations take s, m, h or d')
			->addOption('responses', 'r', InputOption::VALUE_REQUIRED, 'Comma-separated responses, e.g. ban,notify_admin; empty for none')
			->addOption('reset', null, InputOption::VALUE_NONE, 'Put the check back to its defaults');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$id = (string)$input->getArgument('check');
		try {
			$this->registry->get($id);
			if ($input->getOption('reset')) {
				$this->settings->resetCheck($id, 'occ');
				$output->writeln('Reset to defaults.');
				return self::SUCCESS;
			}

			$mode = is_string($input->getOption('mode')) ? strtolower((string)$input->getOption('mode')) : null;
			$params = [];
			foreach ((array)$input->getOption('param') as $assignment) {
				if (!str_contains((string)$assignment, '=')) {
					throw new InvalidParamException('unknown_param', ['param' => (string)$assignment]);
				}
				[$name, $raw] = explode('=', (string)$assignment, 2);
				$params[trim($name)] = $raw;
			}
			$responses = null;
			if (is_string($input->getOption('responses'))) {
				$responses = array_values(array_filter(array_map('trim', explode(',', (string)$input->getOption('responses')))));
			}

			$changes = $this->settings->changeCheck($id, $mode, $responses, $params, 'occ');
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}
		$output->writeln($changes === [] ? 'Nothing changed.' : 'Saved.');
		return self::SUCCESS;
	}
}
