<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;

/**
 * Tells the administrators about detections, aggregated so that an attack
 * cannot turn into thousands of notifications or emails:
 *
 * - Bell: at most one notification per check, source and hour. Further hits
 *   in that hour only raise the counter it shows (the notifier reads it live).
 * - Email: only for detections of at least `notify_admin_email_min_severity`,
 *   and at most one per check and hour. Admins without an email address get
 *   the bell only.
 *
 * A detection with the fact {@see self::FACT_ALERT_KEY} is aggregated per
 * check and that key (bell and email), so that different kinds of changes
 * are each told.
 */
class AdminAlerts {
	public const SUBJECT = 'detection';
	public const OBJECT_TYPE = 'alert';
	/** Counter source key for the email limit, which is per check only */
	public const MAIL_KEY = '@mail';
	/** Detection fact: aggregate by this key instead of the source, for checks that report changes rather than attacks */
	public const FACT_ALERT_KEY = 'alert_key';
	/** Detection fact: also notify the members of the admin group, whatever notify_admin_group says */
	public const FACT_ALL_ADMINS = 'alert_all_admins';

	public const BELL_SENT = 'sent';
	public const BELL_AGGREGATED = 'aggregated';
	public const EMAIL_SENT = 'sent';
	public const EMAIL_LIMITED = 'limited';
	public const EMAIL_BELOW_SEVERITY = 'below_severity';
	public const EMAIL_NO_ADDRESS = 'no_address';
	public const EMAIL_FAILED = 'failed';

	public function __construct(
		private readonly AlertMapper $alerts,
		private readonly AdminRecipients $recipients,
		private readonly INotificationManager $notifications,
		private readonly Mails $mails,
		private readonly Settings $settings,
		private readonly NarrativeBuilder $narratives,
		private readonly CheckRegistry $registry,
		private readonly IFactory $l10nFactory,
		private readonly AdminLinks $links,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return array{alert: int, hits: int, bell: string, email: string, recipients: int}
	 */
	public function alert(Detection $detection): array {
		$now = $this->timeFactory->getTime();
		$bucket = intdiv($now, 3600);
		$checkId = $detection->getCheckId();
		[$alertId, $first] = $this->alerts->hit($checkId, self::sourceKey($detection), $bucket, $detection->getId(), $now);
		$recipients = $this->recipients->users(($detection->getExplanationData()['facts'][self::FACT_ALL_ADMINS] ?? false) === true);

		if ($first) {
			foreach ($recipients as $user) {
				$notification = $this->notifications->createNotification();
				$notification->setApp(Application::APP_ID)
					->setUser($user->getUID())
					->setDateTime(new \DateTime('@' . $now))
					->setObject(self::OBJECT_TYPE, (string)$alertId)
					->setSubject(self::SUBJECT, [
						'alert' => $alertId,
						'detection' => $detection->getId(),
						'check' => $checkId,
					]);
				$this->notifications->notify($notification);
			}
		}

		return [
			'alert' => $alertId,
			'hits' => $this->alerts->find($alertId)['hits'] ?? 1,
			'bell' => $first ? self::BELL_SENT : self::BELL_AGGREGATED,
			'email' => $this->email($detection, $recipients, $bucket, $now),
			'recipients' => count($recipients),
		];
	}

	/**
	 * "Credential stuffing from 203.0.113.7", "One account attacked from many places: alice".
	 */
	public function headline(Detection $detection, IL10N $l): string {
		$custom = $this->customHeadline($detection, $l);
		if ($custom !== null) {
			return $custom;
		}
		$name = $this->checkName($detection->getCheckId(), $l);
		if ($detection->getIp() !== null) {
			return $l->t('%1$s from %2$s', [$name, $detection->getIp()]);
		}
		if ($detection->getUid() !== null) {
			return $l->t('%1$s: account %2$s', [$name, $detection->getUid()]);
		}
		return $name;
	}

	/**
	 * The headline the detection's check gives it, if it names its detections itself.
	 */
	public function customHeadline(Detection $detection, IL10N $l): ?string {
		try {
			$check = $this->registry->check($this->registry->classOf($detection->getCheckId()));
		} catch (InvalidParamException) {
			return null;
		}
		return $check instanceof IHeadlinesDetection ? $check->headline($detection, $l) : null;
	}

	public function checkName(string $checkId, IL10N $l): string {
		try {
			return $this->registry->get($checkId)->texts($l)->name;
		} catch (InvalidParamException) {
			return $checkId;
		}
	}

	/**
	 * The key detections are aggregated by: the address, else the account,
	 * else the whole server.
	 */
	public static function sourceKey(Detection $detection): string {
		$alertKey = self::alertKey($detection);
		if ($alertKey !== null) {
			return $alertKey;
		}
		if ($detection->getIp() !== null) {
			return 'ip:' . $detection->getIp();
		}
		if ($detection->getUid() !== null) {
			return 'u:' . $detection->getUid();
		}
		return 'instance';
	}

	/**
	 * "k:" and a hash of the detection's alert key, short enough for the
	 * counter table whatever the key is; null without one.
	 */
	private static function alertKey(Detection $detection): ?string {
		$key = $detection->getExplanationData()['facts'][self::FACT_ALERT_KEY] ?? null;
		return is_string($key) && $key !== '' ? 'k:' . substr(hash('sha256', $key), 0, 40) : null;
	}

	/**
	 * @param list<IUser> $recipients
	 */
	private function email(Detection $detection, array $recipients, int $bucket, int $now): string {
		$minimum = Severity::tryFrom((string)$this->settings->global(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY));
		$severity = Severity::tryFrom($detection->getSeverity());
		if ($minimum === null || $severity === null || !$severity->atLeast($minimum)) {
			return self::EMAIL_BELOW_SEVERITY;
		}
		$withAddress = array_values(array_filter($recipients, static fn (IUser $u): bool => (string)$u->getEMailAddress() !== ''));
		if ($withAddress === []) {
			return self::EMAIL_NO_ADDRESS;
		}
		$mailKey = self::alertKey($detection);
		$mailKey = $mailKey === null ? self::MAIL_KEY : self::MAIL_KEY . ':' . $mailKey;
		[, $first] = $this->alerts->hit($detection->getCheckId(), $mailKey, $bucket, $detection->getId(), $now);
		if (!$first) {
			return self::EMAIL_LIMITED;
		}
		$sent = 0;
		foreach ($withAddress as $user) {
			if ($this->mails->send($user, $this->mailFor($detection, $user))) {
				$sent++;
			}
		}
		return $sent > 0 ? self::EMAIL_SENT : self::EMAIL_FAILED;
	}

	/**
	 * The alert email about a detection, in the recipient's language.
	 */
	public function mailFor(Detection $detection, IUser $user): MailContent {
		$language = $this->l10nFactory->getUserLanguage($user);
		$l = $this->l10nFactory->get(Application::APP_ID, $language);
		$narrative = $this->narratives->build($detection, $l);
		$headline = $this->headline($detection, $l);
		$paragraphs = $narrative->happened;
		if ($narrative->observedBecause !== null) {
			$paragraphs[] = $narrative->observedBecause;
		}
		$paragraphs[] = $l->t('Further detections of this kind within the hour are not emailed. You find all of them on the admin page.');
		return new MailContent(
			templateId: 'intrusion_detection.adminAlert',
			subject: $l->t('Intrusion detection: %s', [$headline]),
			heading: $headline,
			paragraphs: $paragraphs,
			listHeading: $l->t('What Nextcloud did:'),
			listItems: $narrative->done,
			buttonText: $l->t('Open intrusion detection'),
			buttonUrl: $this->links->detection($detection->getId()),
			language: $language,
		);
	}
}
