<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Traps\ReservedNames as ReservedNamesService;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * List, add and remove the reserved login names of the decoy admin account
 * check, with the same validation as the admin page.
 */
class ReservedNames extends Base {
	public function __construct(
		private readonly ReservedNamesService $names,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:reserved-names')
			->setDescription('List, add or remove reserved login names; any login attempt with one blocks the source')
			->addOption('add', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Reserve a name (not an existing account)')
			->addOption('remove', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Stop reserving a name')
			->addOption('add-suggested', null, InputOption::VALUE_NONE, 'Reserve every suggested name that is not an account');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$add = array_values(array_map('strval', (array)$input->getOption('add')));
		if ($input->getOption('add-suggested')) {
			$add = array_merge($add, $this->names->suggestions());
		}
		$remove = array_values(array_map('strval', (array)$input->getOption('remove')));
		try {
			if ($add !== []) {
				$this->names->add($add, 'occ');
			}
			if ($remove !== []) {
				$this->names->remove($remove, 'occ');
			}
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}

		$data = [
			'reserved' => $this->names->list(),
			'suggested' => $this->names->suggestions(),
			'collisions' => $this->names->collisions(),
		];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $data);
			return self::SUCCESS;
		}
		$output->writeln($data['reserved'] === [] ? 'No names are reserved.' : 'Reserved: ' . implode(', ', $data['reserved']));
		if ($data['suggested'] !== []) {
			$output->writeln('Suggested (not accounts here): ' . implode(', ', $data['suggested']) . '. Add them with --add-suggested.');
		}
		if ($data['collisions'] !== []) {
			$output->writeln('<comment>These reserved names are accounts by now and are skipped: ' . implode(', ', $data['collisions']) . '</comment>');
		}
		return self::SUCCESS;
	}
}
