<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
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
		private readonly BreachedPasswordDetector $breach,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:user')
			->setDescription('Show and lift what intrusion detection applies to an account')
			->addArgument('uid', InputArgument::REQUIRED, 'The account')
			->addOption('end-protection', null, InputOption::VALUE_NONE, 'End the extra protection of the account (logins with its password no longer need confirmation)')
			->addOption('reset-breach-check', null, InputOption::VALUE_NONE, 'Forget the result of the breached password check, so the password is checked again at the next login');
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

		if ($input->getOption('reset-breach-check')) {
			$this->breach->reset($uid);
			$output->writeln('The breached password check of ' . $uid . ' was reset; the password is checked at the next login.');
		}

		$protection = $this->protection->get($uid);
		$checkedAt = $this->breach->checkedAt($uid);
		$state = [
			'uid' => $uid,
			'protected_until' => $protection === null ? null : date('c', $protection['expires_at']),
			'protection_reason' => $protection['reason'] ?? null,
			'protection_detection' => $protection['detection_id'] ?? null,
			'breach_checked_at' => $checkedAt === null ? null : date('c', $checkedAt),
			'breached' => $this->breach->isBreached($uid),
		];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $state);
			return self::SUCCESS;
		}
		$output->writeln($protection === null
			? 'Protection: none.'
			: sprintf('Protection: until %s, because the account is under attack (detection %s). End it with --end-protection.', $state['protected_until'], (string)($state['protection_detection'] ?? '-')));
		$output->writeln(match (true) {
			$state['breach_checked_at'] === null => 'Breached password check: the current password was not checked yet.',
			$state['breached'] => sprintf('Breached password check: the current password was found on the list (checked %s). Reset with --reset-breach-check.', $state['breach_checked_at']),
			default => sprintf('Breached password check: the current password was not found on the list (checked %s).', $state['breach_checked_at']),
		});
		return self::SUCCESS;
	}
}
