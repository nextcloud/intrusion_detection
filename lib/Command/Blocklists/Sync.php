<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Blocklists;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\SyncResult;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Sync extends Base {
	public function __construct(
		private readonly BlocklistSync $sync,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:blocklists:sync')
			->setDescription('Download one list, or every enabled list, now')
			->addArgument('id', InputArgument::OPTIONAL, 'The list to download; all enabled lists when left out')
			->addOption('force', 'f', InputOption::VALUE_NONE, 'Download in full, even if the publisher reports no change');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$id = $input->getArgument('id');
		try {
			$results = $this->sync->sync(is_string($id) ? $id : null, (bool)$input->getOption('force'));
		} catch (\InvalidArgumentException $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return self::INVALID;
		}
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, array_map(static fn (SyncResult $r): array => $r->toArray(), $results));
		} elseif ($results === []) {
			$output->writeln('No list is enabled.');
		}
		$failed = false;
		foreach ($results as $result) {
			$failed = $failed || $result->outcome === SyncResult::FAILED;
			if ($input->getOption('output') === self::OUTPUT_FORMAT_PLAIN) {
				$output->writeln(match ($result->outcome) {
					SyncResult::UPDATED => sprintf('%s: updated, %d range(s).', $result->listId, $result->ranges),
					SyncResult::UNCHANGED => sprintf('%s: unchanged, %d range(s).', $result->listId, $result->ranges),
					SyncResult::SKIPPED => sprintf('%s: skipped, another sync is running.', $result->listId),
					default => sprintf('<error>%s: not taken (%s); the previous version stays in use.</error>', $result->listId, (string)$result->error),
				});
			}
		}
		return $failed ? self::FAILURE : self::SUCCESS;
	}
}
