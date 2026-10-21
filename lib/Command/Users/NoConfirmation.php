<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Users;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The active accounts with neither a second factor nor an email address:
 * if a check asks them to confirm a login, nothing can (concept section
 * 11.5). The same list as on the Confirmation tab.
 */
class NoConfirmation extends Base {
	public function __construct(
		private readonly ConfirmationCoverage $coverage,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:users:no-confirmation')
			->setDescription('List the active accounts with neither a second factor nor an email address')
			->addOption('admins', null, InputOption::VALUE_NONE, 'Only members of the admin group')
			->addOption('limit', 'l', InputOption::VALUE_REQUIRED, 'At most this many', '100')
			->addOption('offset', null, InputOption::VALUE_REQUIRED, 'Skip this many', '0');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$this->coverage->refresh();
		$admins = (bool)$input->getOption('admins');
		$list = $this->coverage->list((int)$input->getOption('limit'), max(0, (int)$input->getOption('offset')), $admins);
		$counts = $this->coverage->users();
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, [
				'without_method' => $admins ? count($this->coverage->admins()['withNeither']) : $counts['withoutMethod'],
				'active' => $counts['active'],
				'accounts' => $list,
			]);
			return self::SUCCESS;
		}
		$output->writeln($admins
			? sprintf('%d administrators have neither a second factor nor an email address.', count($this->coverage->admins()['withNeither']))
			: sprintf('%d of %d active accounts have neither a second factor nor an email address.', $counts['withoutMethod'], $counts['active']));
		if ($list === []) {
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Account', 'Name', 'Last login', 'Groups']);
		foreach ($list as $row) {
			$table->addRow([$row['uid'], $row['displayName'], $row['lastLogin'] > 0 ? date('Y-m-d H:i', $row['lastLogin']) : '-', implode(', ', $row['groups'])]);
		}
		$table->render();
		return self::SUCCESS;
	}
}
