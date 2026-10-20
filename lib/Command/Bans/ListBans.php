<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Bans;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ListBans extends Base {
	public function __construct(
		private readonly BanMapper $mapper,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:bans:list')
			->setDescription('List blocked addresses and networks')
			->addOption('all', 'a', InputOption::VALUE_NONE, 'Include expired and lifted blocks')
			->addOption('limit', 'l', InputOption::VALUE_REQUIRED, 'At most this many', '200');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$now = $this->timeFactory->getTime();
		$bans = $this->mapper->findList($now, (bool)$input->getOption('all'), max(1, min(10000, (int)$input->getOption('limit'))));
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, array_map(static fn (Ban $b): array => $b->jsonSerialize(), $bans));
			return self::SUCCESS;
		}
		if ($bans === []) {
			$output->writeln('No active blocks.');
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Id', 'Reference', 'Address', 'Level', 'Check', 'Since', 'Until', 'State']);
		foreach ($bans as $ban) {
			$table->addRow([
				$ban->getId(),
				$ban->getDisplayReference(),
				$ban->getCidr(),
				$ban->getLevel(),
				$ban->getCheckId(),
				date('Y-m-d H:i', $ban->getCreatedAt()),
				date('Y-m-d H:i', $ban->getExpiresAt()),
				$ban->getLiftedAt() !== null ? 'lifted by ' . $ban->getLiftedBy() : ($ban->isActive($now) ? 'active' : 'expired'),
			]);
		}
		$table->render();
		return self::SUCCESS;
	}
}
