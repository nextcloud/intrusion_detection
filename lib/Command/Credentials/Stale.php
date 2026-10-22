<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Credentials;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Db\StaleTokenMapper;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IToken;
use OCP\IUserManager;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * App passwords and remembered browsers nobody used for a number of days,
 * of every account or one: list them, and with --revoke remove them and
 * tell each user once. Shows ids, names and last use, never a secret.
 */
class Stale extends Base {
	/** Removing takes at least this many days without use */
	public const MIN_REVOKE_DAYS = 30;
	private const PAGE = 1000;

	public function __construct(
		private readonly StaleTokenMapper $mapper,
		private readonly StaleCredentialSweep $sweep,
		private readonly IUserManager $userManager,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:credentials:stale')
			->setDescription('List the app passwords and remembered browsers nobody used for a while, and optionally remove them')
			->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'Only this account')
			->addOption('days', 'd', InputOption::VALUE_REQUIRED, 'Unused for at least this many days', (string)StaleCredentials::DAYS)
			->addOption('revoke', null, InputOption::VALUE_NONE, 'Remove them and tell each user once (at least ' . self::MIN_REVOKE_DAYS . ' days)');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$days = (string)$input->getOption('days');
		if (!preg_match('/^\d{1,5}$/', $days) || (int)$days < 1) {
			$output->writeln('<error>--days must be a whole number of at least 1.</error>');
			return self::INVALID;
		}
		$days = (int)$days;
		$revoke = (bool)$input->getOption('revoke');
		if ($revoke && $days < self::MIN_REVOKE_DAYS) {
			$output->writeln(sprintf('<error>Removing needs --days of at least %d, so that devices in use are not logged out.</error>', self::MIN_REVOKE_DAYS));
			return self::INVALID;
		}
		$uid = $input->getOption('user');
		if ($uid !== null && $this->userManager->get((string)$uid) === null) {
			$output->writeln(sprintf('<error>There is no account "%s".</error>', (string)$uid));
			return self::INVALID;
		}
		$uid = $uid === null ? null : (string)$uid;
		$before = $this->timeFactory->getTime() - $days * 86400;

		$credentials = [];
		$afterId = 0;
		do {
			$page = $this->mapper->tokens($before, $uid, $afterId, self::PAGE);
			foreach ($page as $token) {
				$afterId = $token['id'];
				$credentials[] = [
					'id' => $token['id'],
					'user' => $token['uid'],
					'type' => $token['type'] === IToken::PERMANENT_TOKEN ? StaleCredentials::KIND_APP_PASSWORD : StaleCredentials::KIND_SESSION,
					'name' => $token['type'] === IToken::PERMANENT_TOKEN ? Tokens::cleanName($token['name']) : self::browser($token['name']),
					'last_used' => $token['lastActivity'],
				];
			}
		} while (count($page) === self::PAGE);
		$accounts = array_values(array_unique(array_column($credentials, 'user')));

		$removed = 0;
		if ($revoke) {
			foreach ($accounts as $account) {
				$removed += $this->sweep->remove($account, $before, $days, 'an administrator with occ');
			}
			$this->sweep->recount();
		}

		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$data = ['days' => $days, 'accounts' => count($accounts), 'credentials' => $credentials];
			if ($revoke) {
				$data['removed'] = $removed;
			}
			$this->writeArrayInOutputFormat($input, $output, $data);
			return self::SUCCESS;
		}
		if ($credentials === []) {
			$output->writeln(sprintf('No app password or remembered browser has gone unused for %d days.', $days));
			return self::SUCCESS;
		}
		$found = count($credentials);
		$output->writeln(sprintf(
			'%d %s of %d %s %s not been used for %d days.',
			$found,
			$found === 1 ? 'app password or remembered browser' : 'app passwords and remembered browsers',
			count($accounts),
			count($accounts) === 1 ? 'account' : 'accounts',
			$found === 1 ? 'has' : 'have',
			$days,
		));
		$table = new Table($output);
		$table->setHeaders(['Id', 'Account', 'Type', 'Name', 'Last used']);
		foreach ($credentials as $row) {
			$table->addRow([$row['id'], $row['user'], $row['type'] === StaleCredentials::KIND_APP_PASSWORD ? 'app password' : 'browser', $row['name'], date('Y-m-d H:i', $row['last_used'])]);
		}
		$table->render();
		if ($revoke) {
			$output->writeln(sprintf('<info>Removed %d of them; each user was told once.</info>', $removed));
		} else {
			$output->writeln('To remove them, run this again with --revoke.');
		}
		return self::SUCCESS;
	}

	/**
	 * A browser session's name is its user agent: "Firefox on Linux", or the cleaned text when neither is known.
	 */
	private static function browser(string $userAgent): string {
		[$family, $platform] = DeviceLabel::parse($userAgent);
		return $family === DeviceLabel::OTHER && $platform === DeviceLabel::OTHER ? Tokens::cleanName($userAgent) : DeviceLabel::english($family, $platform);
	}
}
