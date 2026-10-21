<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCP\IUserManager;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Show what intrusion detection currently applies to one account, and lift
 * it. Each flag lifts one kind of state; without flags the state is shown.
 */
class User extends Base {
	public function __construct(
		private readonly IUserManager $userManager,
		private readonly AccountProtection $protection,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:user')
			->setDescription('Show and lift what intrusion detection applies to an account')
			->addArgument('uid', InputArgument::REQUIRED, 'The account')
			->addOption('end-protection', null, InputOption::VALUE_NONE, 'End the extra protection of the account (logins with its password no longer need confirmation)');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$uid = (string)$input->getArgument('uid');
		if (!$this->userManager->userExists($uid)) {
			$output->writeln('<error>There is no such account.</error>');
			return self::INVALID;
		}

		if ($input->getOption('end-protection')) {
			$output->writeln($this->protection->end($uid, 'occ')
				? 'The protection of ' . $uid . ' has ended.'
				: $uid . ' was not under protection.');
		}

		$protection = $this->protection->get($uid);
		$state = [
			'uid' => $uid,
			'protected_until' => $protection === null ? null : date('c', $protection['expires_at']),
			'protection_reason' => $protection['reason'] ?? null,
			'protection_detection' => $protection['detection_id'] ?? null,
		];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $state);
			return self::SUCCESS;
		}
		$output->writeln($protection === null
			? 'Protection: none.'
			: sprintf('Protection: until %s, because the account is under attack (detection %s). End it with --end-protection.', $state['protected_until'], (string)($state['protection_detection'] ?? '-')));
		return self::SUCCESS;
	}
}
