<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Checks;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
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
		private readonly AuditLogger $audit,
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
			$check = $this->registry->get($id);
			if ($input->getOption('reset')) {
				$this->settings->resetCheck($id);
				$this->audit->log('check %s reset to defaults by %s', ['check' => $id, 'actor' => 'occ']);
				$output->writeln('Reset to defaults.');
				return self::SUCCESS;
			}

			// Validate everything first, then save.
			$mode = null;
			if (is_string($input->getOption('mode'))) {
				$mode = Mode::tryFrom(strtolower((string)$input->getOption('mode'))) ?? throw new InvalidParamException('unknown_mode');
			}
			$params = [];
			foreach ((array)$input->getOption('param') as $assignment) {
				if (!str_contains((string)$assignment, '=')) {
					throw new InvalidParamException('unknown_param', ['param' => (string)$assignment]);
				}
				[$name, $raw] = explode('=', (string)$assignment, 2);
				$params[trim($name)] = $check->param(trim($name))->parse($raw);
			}
			$responses = null;
			if (is_string($input->getOption('responses'))) {
				$responses = [];
				foreach (array_filter(array_map('trim', explode(',', (string)$input->getOption('responses')))) as $value) {
					$response = ResponseType::tryFrom($value);
					if ($response === null || !$check->allowsResponse($response)) {
						throw new InvalidParamException('unknown_response', ['response' => $value]);
					}
					$responses[] = $response;
				}
			}

			$changes = $this->settings->updateCheck($id, $mode, $params, $responses);
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}
		if ($changes === []) {
			$output->writeln('Nothing changed.');
			return self::SUCCESS;
		}
		$this->audit->log('check %s changed by %s: %s', [
			'check' => $id,
			'actor' => 'occ',
			'change' => json_encode($changes),
		]);
		$output->writeln('Saved.');
		return self::SUCCESS;
	}
}
