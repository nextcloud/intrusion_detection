<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Decoys;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCP\AppFramework\Db\DoesNotExistException;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Delete extends Base {
	public function __construct(
		private readonly DecoyService $decoys,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:decoys:delete')
			->setDescription('Delete a decoy credential; using it is no longer detected')
			->addArgument('id', InputArgument::REQUIRED, 'The decoy id, see intrusion:decoys:list');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		try {
			$decoy = $this->decoys->delete((string)$input->getArgument('id'), 'occ');
		} catch (DoesNotExistException) {
			$output->writeln('<error>There is no such decoy.</error>');
			return self::FAILURE;
		}
		$output->writeln('Deleted decoy ' . (string)$decoy->getId() . ' ("' . $decoy->getLabel() . '").');
		return self::SUCCESS;
	}
}
