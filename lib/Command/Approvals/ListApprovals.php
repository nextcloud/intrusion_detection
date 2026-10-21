<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Approvals;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Db\Approval;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ListApprovals extends Base {
	public function __construct(
		private readonly ApprovalService $approvals,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:approvals:list')
			->setDescription('List requests that wait for the approval of a second administrator')
			->addOption('all', 'a', InputOption::VALUE_NONE, 'Include decided and expired requests of the last 90 days')
			->addOption('limit', 'l', InputOption::VALUE_REQUIRED, 'At most this many', '200');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$approvals = $this->approvals->list(!$input->getOption('all'), max(1, min(10000, (int)$input->getOption('limit'))));
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, array_map(static fn (Approval $a): array => $a->jsonSerialize(), $approvals));
			return self::SUCCESS;
		}
		if ($approvals === []) {
			$output->writeln('No pending requests.');
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Id', 'Account', 'Group', 'Asked by', 'Asked at', 'Expires', 'Status', 'Decided by']);
		foreach ($approvals as $approval) {
			$table->addRow([
				$approval->getId(),
				$approval->getSubjectUid(),
				$approval->getGroupId(),
				$approval->getRequestedBy(),
				date('Y-m-d H:i', $approval->getCreatedAt()),
				date('Y-m-d H:i', $approval->getExpiresAt()),
				$approval->getStatus(),
				$approval->getDecidedBy() ?? '',
			]);
		}
		$table->render();
		return self::SUCCESS;
	}
}
