<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDateTimeZone;
use OCP\IUser;
use OCP\Mail\IEmailValidator;
use Psr\Log\LoggerInterface;

/**
 * Sends the admin digest when it is due, once per period, to the members of
 * the notification groups that have an email address. Admins without one
 * are skipped; the admin page says so.
 *
 * "Once per period" holds across web servers and concurrent cron runs: the
 * period is claimed with a counter in ids_alerts, whose unique index lets
 * exactly one run insert it ({@see AlertMapper::hit()}).
 *
 * @psalm-import-type IntrusionDetectionDigest from ResponseDefinitions
 */
class DigestSender {
	public const CLAIM_CHECK = 'digest';
	public const CLAIM_SOURCE = '@digest';
	/** Admins without email listed by name on the admin page */
	public const MAX_LISTED = 20;

	public const RESULT_OFF = 'off';
	public const RESULT_NOT_DUE = 'not_due';
	public const RESULT_ALREADY_SENT = 'already_sent';
	public const RESULT_QUIET_SKIPPED = 'quiet_skipped';
	public const RESULT_NO_RECIPIENTS = 'no_recipients';
	public const RESULT_SENT = 'sent';
	public const RESULT_FAILED = 'failed';

	public const TEST_SENT = 'sent';
	public const TEST_NO_ADDRESS = 'no_address';
	public const TEST_FAILED = 'failed';

	public function __construct(
		private readonly Settings $settings,
		private readonly Digest $digest,
		private readonly AdminRecipients $recipients,
		private readonly Mails $mails,
		private readonly AlertMapper $alerts,
		private readonly IEmailValidator $emailValidator,
		private readonly UserMessages $messages,
		private readonly IDateTimeZone $dateTimeZone,
		private readonly Prerequisites $prerequisites,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	public function schedule(): DigestSchedule {
		return new DigestSchedule((string)$this->settings->global(GlobalSettings::DIGEST_FREQUENCY), $this->dateTimeZone->getDefaultTimeZone());
	}

	/**
	 * Send the digest if one is due and nobody sent it yet.
	 *
	 * @return self::RESULT_*
	 */
	public function sendIfDue(): string {
		$schedule = $this->schedule();
		$now = $this->timeFactory->getTime();
		$due = $schedule->lastDue($now);
		if ($due === null) {
			return self::RESULT_OFF;
		}
		// No digest for a period that ended before the app was installed.
		if (!$schedule->isWithinGrace($due, $now) || $due < $this->settings->getInt(GlobalSettings::INSTALLED_AT)) {
			return self::RESULT_NOT_DUE;
		}
		if ((int)($this->settings->getJson(GlobalSettings::DIGEST_STATE)['period'] ?? 0) >= $due) {
			return self::RESULT_ALREADY_SENT;
		}
		[, $first] = $this->alerts->hit(self::CLAIM_CHECK, self::CLAIM_SOURCE, intdiv($due, 3600), null, $now);
		if (!$first) {
			return self::RESULT_ALREADY_SENT;
		}

		[$withEmail, $withoutEmail] = $this->splitRecipients();
		$report = $this->digest->report($schedule, $due);
		$result = self::RESULT_SENT;
		$sent = 0;
		$failed = 0;
		if ($report->isQuiet() && !$this->settings->getBool(GlobalSettings::DIGEST_SEND_QUIET)) {
			$result = self::RESULT_QUIET_SKIPPED;
		} elseif ($withEmail === []) {
			$result = self::RESULT_NO_RECIPIENTS;
		} else {
			/** @var array<string, MailContent> $byReader */
			$byReader = [];
			foreach ($withEmail as $user) {
				$l = $this->messages->l10nFor($user);
				$timeZone = $this->messages->timeZoneOf($user);
				$reader = $l->getLanguageCode() . ' ' . $l->getLocaleCode() . ' ' . $timeZone->getName();
				$byReader[$reader] ??= $this->digest->content($report, $l, $timeZone);
				if ($this->mails->send($user, $byReader[$reader])) {
					$sent++;
				} else {
					$failed++;
				}
			}
			if ($sent === 0) {
				$result = self::RESULT_FAILED;
			}
		}

		$this->settings->setGlobal(GlobalSettings::DIGEST_STATE, json_encode([
			'period' => $due,
			'sentAt' => $now,
			'result' => $result,
			'recipients' => $sent,
			'failed' => $failed,
			'withoutEmail' => count($withoutEmail),
		], JSON_THROW_ON_ERROR));
		if ($result === self::RESULT_FAILED) {
			$this->logger->error('Intrusion detection could not send the admin digest to any of {count} recipients', ['count' => $failed]);
		}
		return $result;
	}

	/**
	 * Send a digest of the period up to now to one admin only, marked as a
	 * test. It does not count as the period's digest.
	 *
	 * @return self::TEST_*
	 */
	public function sendTest(IUser $admin): string {
		if (!$this->hasAddress($admin)) {
			return self::TEST_NO_ADDRESS;
		}
		$report = $this->digest->report($this->schedule(), $this->timeFactory->getTime());
		$content = $this->digest->content($report, $this->messages->l10nFor($admin), $this->messages->timeZoneOf($admin), true);
		return $this->mails->send($admin, $content) ? self::TEST_SENT : self::TEST_FAILED;
	}

	/**
	 * The digest settings and who gets it, for the admin page.
	 *
	 * @return IntrusionDetectionDigest
	 */
	public function overview(?IUser $viewer): array {
		$schedule = $this->schedule();
		$now = $this->timeFactory->getTime();
		[$withEmail, $withoutEmail] = $this->splitRecipients();
		$state = $this->settings->getJson(GlobalSettings::DIGEST_STATE);
		$listed = array_slice($withoutEmail, 0, self::MAX_LISTED);
		return [
			'frequency' => $schedule->isOff() ? DigestSchedule::OFF : $schedule->frequency,
			'sendQuiet' => $this->settings->getBool(GlobalSettings::DIGEST_SEND_QUIET),
			'timezone' => $schedule->timezone->getName(),
			'nextDue' => $schedule->nextDue($now),
			'last' => isset($state['period'], $state['sentAt']) ? [
				'period' => (int)$state['period'],
				'sentAt' => (int)$state['sentAt'],
				'result' => (string)($state['result'] ?? ''),
				'recipients' => (int)($state['recipients'] ?? 0),
				'failed' => (int)($state['failed'] ?? 0),
			] : null,
			'recipients' => count($withEmail),
			'withoutEmail' => array_map(static fn (IUser $user): array => ['uid' => $user->getUID(), 'displayName' => $user->getDisplayName()], $listed),
			'withoutEmailCount' => count($withoutEmail),
			'mailConfigured' => $this->prerequisites->hasMail(),
			'viewerHasEmail' => $viewer !== null && $this->hasAddress($viewer),
		];
	}

	/**
	 * @return array{0: list<IUser>, 1: list<IUser>} the recipients with and without an email address
	 */
	private function splitRecipients(): array {
		$with = [];
		$without = [];
		foreach ($this->recipients->users() as $user) {
			if ($this->hasAddress($user)) {
				$with[] = $user;
			} else {
				$without[] = $user;
			}
		}
		return [$with, $without];
	}

	private function hasAddress(IUser $user): bool {
		$address = $user->getEMailAddress();
		return $address !== null && $address !== '' && $this->emailValidator->isValid($address);
	}
}
