<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\StaleCredential;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Db\StaleTokenMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\Config\ValueType;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;

/**
 * The daily look at app passwords and remembered browser sessions nobody
 * used for {@see StaleCredentials::DAYS} days, across all accounts:
 *
 * - With automatic removal on (`stale_credentials_remove_days`), an
 *   account's credentials unused for that long are removed, and the user
 *   is told once what was removed.
 * - Otherwise the user is reminded, at most every REMIND_EVERY seconds and
 *   only when a credential became stale since the last reminder. Only the
 *   time of the last reminder is kept, as a user preference.
 * - The instance-wide counts for the administrators are stored.
 *
 * The accounts are read a page at a time, grouped in the database, so a run
 * costs a few queries plus a few per user it reminds or removes for. At
 * most MAX_REMINDERS users are reminded per run; the others follow on the
 * next days. The hourly status job runs it once every RUN_EVERY seconds.
 */
class StaleCredentialSweep {
	public const REMIND_EVERY = 30 * 86400;
	/** Accounts read per query */
	public const PAGE = 1000;
	public const MAX_REMINDERS = 1000;
	/** Stored counts older than this are counted again when read; the hourly job counts again in between runs */
	public const COUNT_TTL = 3600;
	/** Less than a day, so that an hourly job that starts a little early still runs it daily */
	public const RUN_EVERY = 86400 - 1800;

	public function __construct(
		private readonly StaleTokenMapper $mapper,
		private readonly StaleCredentials $credentials,
		private readonly StaleCredentialNotices $notices,
		private readonly Settings $settings,
		private readonly IUserConfig $userConfig,
		private readonly IUserManager $userManager,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Run when the last run is a day ago; otherwise only count again.
	 *
	 * @return ?array{accounts: int, credentials: int, reminded: int, removed: int} null when it was not due
	 */
	public function runIfDue(): ?array {
		$ranAt = $this->settings->getJson(GlobalSettings::STALE_CREDENTIALS)['ranAt'] ?? 0;
		if ($this->timeFactory->getTime() - (is_int($ranAt) ? $ranAt : 0) < self::RUN_EVERY) {
			$this->recount();
			return null;
		}
		return $this->run();
	}

	/**
	 * @return array{accounts: int, credentials: int, reminded: int, removed: int}
	 */
	public function run(): array {
		if (!$this->settings->isEnabled()) {
			return ['accounts' => 0, 'credentials' => 0, 'reminded' => 0, 'removed' => 0];
		}
		$now = $this->timeFactory->getTime();
		$removeDays = $this->removeDays();
		$removeBefore = $removeDays === 0 ? null : $now - $removeDays * 86400;
		/** @var array<string, int> $remindedAt */
		$remindedAt = $this->userConfig->getValuesByUsers(Application::APP_ID, UserKeys::STALE_CREDENTIALS_NOTIFIED_AT, ValueType::INT);
		$reminded = 0;
		$removed = 0;
		$after = null;
		do {
			$page = $this->mapper->accounts($this->credentials->cutoff(), $after, self::PAGE);
			foreach ($page as $account) {
				$uid = $account['uid'];
				$after = $uid;
				try {
					if ($removeBefore !== null && $account['oldest'] < $removeBefore) {
						$removed += $this->remove($uid, $removeBefore, $removeDays);
						continue;
					}
					$last = (int)($remindedAt[$uid] ?? 0);
					if ($reminded >= self::MAX_REMINDERS || $now - $last < self::REMIND_EVERY || $last >= $account['newest'] + StaleCredentials::DAYS * 86400) {
						continue;
					}
					if ($this->userManager->get($uid)?->isEnabled() !== true) {
						continue;
					}
					$this->notices->remind($uid, $account['appPasswords'], $account['sessions']);
					$this->userConfig->setValueInt($uid, Application::APP_ID, UserKeys::STALE_CREDENTIALS_NOTIFIED_AT, $now);
					$reminded++;
				} catch (\Throwable $e) {
					$this->logger->error('Intrusion detection could not handle the unused app passwords and devices of {uid}', ['uid' => $uid, 'exception' => $e]);
				}
			}
		} while (count($page) === self::PAGE);
		$counts = $this->recount($now);
		return ['accounts' => $counts['accounts'], 'credentials' => $counts['credentials'], 'reminded' => $reminded, 'removed' => $removed];
	}

	/**
	 * Days without use after which the daily job removes a credential; 0 when it does not.
	 */
	public function removeDays(): int {
		$days = $this->settings->getInt(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS);
		return $days === 0 ? 0 : max(GlobalSettings::STALE_CREDENTIALS_MIN_REMOVE_DAYS, $days);
	}

	/**
	 * Remove an account's credentials unused since $before, and tell the user once.
	 *
	 * @param string $by who removed them, for the audit log
	 * @return int how many were removed
	 */
	public function remove(string $uid, int $before, int $days, string $by = 'the daily job'): int {
		$gone = $this->credentials->removeUnusedSince($uid, $before, $by);
		if ($gone !== [] && $this->userManager->get($uid)?->isEnabled() === true) {
			$this->notices->removed($uid, $gone, $days);
		}
		return count($gone);
	}

	/**
	 * The instance-wide counts as stored by the last run; counted now when
	 * none were stored or the job did not run for a while.
	 *
	 * @return array{credentials: int, accounts: int, countedAt: int}
	 */
	public function counts(): array {
		$stored = $this->settings->getJson(GlobalSettings::STALE_CREDENTIALS);
		if (is_int($stored['credentials'] ?? null) && is_int($stored['accounts'] ?? null) && is_int($stored['countedAt'] ?? null)
			&& $this->timeFactory->getTime() - $stored['countedAt'] <= self::COUNT_TTL) {
			return ['credentials' => $stored['credentials'], 'accounts' => $stored['accounts'], 'countedAt' => $stored['countedAt']];
		}
		return $this->recount();
	}

	/**
	 * Count again and store the counts.
	 *
	 * @param ?int $ranAt when a run ended; the last run's time is kept otherwise
	 * @return array{credentials: int, accounts: int, countedAt: int}
	 */
	public function recount(?int $ranAt = null): array {
		$counts = $this->mapper->count($this->credentials->cutoff()) + ['countedAt' => $this->timeFactory->getTime()];
		$ranAt ??= $this->settings->getJson(GlobalSettings::STALE_CREDENTIALS)['ranAt'] ?? 0;
		$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS, $counts + ['ranAt' => is_int($ranAt) ? $ranAt : 0]);
		return $counts;
	}
}
