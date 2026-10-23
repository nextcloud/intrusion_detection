<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Decoys;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Decoy\Db\Decoy;
use OCA\IntrusionDetection\Decoy\DecoyService;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class ListDecoys extends Base {
	public function __construct(
		private readonly DecoyService $decoys,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:decoys:list')
			->setDescription('List the decoy credentials and when they were last used');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$decoys = $this->decoys->list();
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, array_map(static fn (Decoy $d): array => $d->jsonSerialize(), $decoys));
			return self::SUCCESS;
		}
		if ($decoys === []) {
			$output->writeln('No decoy credentials. Create one with occ intrusion:decoys:create --label="…".');
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Id', 'Label', 'Account name', 'Format', 'Created', 'By', 'Last used', 'Uses']);
		foreach ($decoys as $decoy) {
			$table->addRow([
				(string)$decoy->getId(),
				$decoy->getLabel(),
				$decoy->getLoginName() ?? '',
				$decoy->getFormat(),
				$decoy->getCreatedAt()?->format('Y-m-d H:i') ?? '',
				$decoy->getCreatedBy() ?? '',
				$decoy->getLastTriggeredAt() === null ? 'never' : date('Y-m-d H:i', $decoy->getLastTriggeredAt()),
				$decoy->getTriggerCount(),
			]);
		}
		$table->render();
		$collisions = $this->decoys->loginNameCollisions();
		if ($collisions !== []) {
			$output->writeln('<comment>These decoy account names are real accounts by now and are skipped: ' . implode(', ', $collisions) . '</comment>');
		}
		return self::SUCCESS;
	}
}
