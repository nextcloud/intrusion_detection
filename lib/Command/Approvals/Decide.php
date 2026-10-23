<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Approvals;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Db\Approval;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Approve or reject a request on the command line, with the same rules as
 * the admin page. occ counts as the second administrator only when it names
 * one with --as: that account must be in the admin group and must be neither
 * the one who asked nor the account the request is about. The decision is
 * written to the audit log with that name.
 */
class Decide extends Base {
	public function __construct(
		private readonly ApprovalService $approvals,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:approvals:decide')
			->setDescription('Approve or reject a request that waits for the approval of a second administrator')
			->addArgument('id', InputArgument::REQUIRED, 'The request, see intrusion:approvals:list')
			->addOption('approve', null, InputOption::VALUE_NONE, 'Approve the request: the account joins the group, the settings change is made, or the waiting login continues')
			->addOption('reject', null, InputOption::VALUE_NONE, 'Reject the request: nothing changes')
			->addOption('as', null, InputOption::VALUE_REQUIRED, 'The administrator who decides; required to approve');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$approve = (bool)$input->getOption('approve');
		$reject = (bool)$input->getOption('reject');
		if ($approve === $reject) {
			$output->writeln('<error>Give either --approve or --reject.</error>');
			return self::INVALID;
		}
		$id = (string)$input->getArgument('id');
		if (!preg_match('/^\d{1,18}$/', $id)) {
			$output->writeln('<error>The id must be a number.</error>');
			return self::INVALID;
		}
		$as = $input->getOption('as');
		$as = is_string($as) && trim($as) !== '' ? trim($as) : null;
		if ($approve && $as === null) {
			$output->writeln('<error>Approving needs --as=<uid>: the administrator who approves, other than the one who asked.</error>');
			return self::INVALID;
		}

		try {
			$approval = $approve
				? $this->approvals->approve((int)$id, (string)$as, ApprovalService::VIA_OCC)
				: $this->approvals->reject((int)$id, $as, ApprovalService::VIA_OCC);
		} catch (ApprovalException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::FAILURE;
		}
		if ($approval->getKind() === Approval::KIND_LOGIN) {
			$output->writeln($approve
				? sprintf('Approved: the login of %s from %s continues.', $approval->getSubjectUid(), $approval->getIp() ?? 'an unknown address')
				: sprintf('Rejected: the login of %s from %s is ended.', $approval->getSubjectUid(), $approval->getIp() ?? 'an unknown address'));
			return self::SUCCESS;
		}
		if ($approval->getKind() === Approval::KIND_SETTINGS) {
			$output->writeln($approve
				? sprintf('Approved: the settings change asked by %s was made.', $approval->getRequestedBy())
				: sprintf('Rejected: the settings change asked by %s was not made.', $approval->getRequestedBy()));
			return self::SUCCESS;
		}
		$output->writeln($approve
			? sprintf('Approved: %s joined %s.', $approval->getSubjectUid(), (string)$approval->getGroupId())
			: sprintf('Rejected: %s did not join %s.', $approval->getSubjectUid(), (string)$approval->getGroupId()));
		return self::SUCCESS;
	}
}
