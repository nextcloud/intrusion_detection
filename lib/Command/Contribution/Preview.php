<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Contribution;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Blocklist\BlocklistContribution;
use OCA\IntrusionDetection\Blocklist\ContributionOverview;
use OCA\IntrusionDetection\Blocklist\ContributionSettings;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Preview extends Base {
	public function __construct(
		private readonly BlocklistContribution $contribution,
		private readonly ContributionSettings $config,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:contribution:preview')
			->setDescription('Show exactly what the next run would send to the shared blocklist, or why it would send nothing');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$batch = $this->contribution->preview();
		$status = ContributionOverview::texts($this->l, $batch->reason)['status'];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, [
				'reason' => $batch->reason,
				'status' => $status,
				'url' => $batch->payload === null ? null : $this->config->url(),
				'windowStart' => $batch->windowStart,
				'windowEnd' => $batch->windowEnd,
				'truncated' => $batch->truncated,
				'payload' => $batch->payload,
			]);
			return self::SUCCESS;
		}
		$output->writeln($status);
		if ($batch->payload === null) {
			return self::SUCCESS;
		}
		$output->writeln(sprintf(
			'Blocks from %s to %s, sent by POST to %s:',
			gmdate('Y-m-d H:i:s', $batch->windowStart) . ' UTC',
			gmdate('Y-m-d H:i:s', $batch->windowEnd) . ' UTC',
			$this->config->url() === '' ? '(no address set)' : $this->config->url(),
		));
		if ($batch->truncated) {
			$output->writeln(sprintf('More addresses were blocked than one run sends; only the first %d are included.', BlocklistContribution::MAX_REPORTS));
		}
		$output->writeln($batch->body(), OutputInterface::OUTPUT_RAW);
		return self::SUCCESS;
	}
}
