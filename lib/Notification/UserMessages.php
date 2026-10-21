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
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\Config\IUserConfig;
use OCP\IDateTimeZone;
use OCP\IL10N;
use OCP\IUser;
use OCP\L10N\IFactory;
use Psr\Container\ContainerInterface;

/**
 * Builds what the affected user is told about a detection: the check's own
 * words ({@see IExplainsToUser}), when it happened in the user's time zone,
 * the address and the kind of device, what Nextcloud did, and what to do.
 *
 * Users never see thresholds, other accounts or anything meant for the
 * administrators, nor a user agent or session name as it was sent: an
 * attacker chooses those, and they would read like part of a genuine
 * security message. Devices are named by {@see DeviceLabel::describe()};
 * app passwords by the name their user gave them, cleaned so that it
 * cannot pass for a link ({@see self::appPasswordName()}).
 */
class UserMessages {
	/** User agents are cut to this length */
	public const MAX_USER_AGENT = 200;
	/** App password names are cut to this length */
	public const MAX_APP_PASSWORD_NAME = 40;
	/** At most this many blocked addresses are named */
	public const MAX_ADDRESSES = 3;

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly ContainerInterface $container,
		private readonly DateFormatter $dates,
		private readonly IFactory $l10nFactory,
		private readonly IUserConfig $userConfig,
		private readonly IDateTimeZone $dateTimeZone,
		private readonly UserLinks $links,
		private readonly Questions $questions,
	) {
	}

	/**
	 * The app's translations in the user's language and locale.
	 */
	public function l10nFor(IUser $user, ?string $language = null): IL10N {
		$locale = $this->userConfig->getValueString($user->getUID(), 'core', 'locale');
		return $this->l10nFactory->get(Application::APP_ID, $language ?? $this->l10nFactory->getUserLanguage($user), $locale !== '' ? $locale : null);
	}

	/**
	 * @param bool $onSecurityPage for the user's security page, which shows the answers itself
	 */
	public function build(Detection $detection, IUser $user, ?string $language = null, bool $onSecurityPage = false): UserMessage {
		$l = $this->l10nFor($user, $language);
		$notice = $this->notice($detection, $l);
		$advice = $notice->advice !== [] ? $notice->advice : [$l->t('If this was not you, change your password and check your devices and sessions in your security settings.')];
		if (!$onSecurityPage && $this->questions->isOpen($detection)) {
			$advice[] = $l->t('Was this you? Answer "Yes, it was me" or "No, it was not me" in the notification about it in Nextcloud.');
		}
		return new UserMessage(
			$notice->subject,
			$notice->message,
			$this->when($detection, $user, $l),
			$this->done($detection, $l),
			$advice,
			$l->getLanguageCode(),
		);
	}

	public function mail(Detection $detection, IUser $user): MailContent {
		$message = $this->build($detection, $user);
		$l = $this->l10nFor($user, $message->language);
		return new MailContent(
			templateId: 'intrusion_detection.userNotice',
			subject: $l->t('Security notice: %s', [$message->subject]),
			heading: $message->subject,
			paragraphs: array_merge($message->happened, [$message->when]),
			listHeading: $message->done === [] ? '' : $l->t('What Nextcloud did:'),
			listItems: $message->done,
			buttonText: $l->t('Open your security settings'),
			buttonUrl: $this->links->securityPage(),
			language: $message->language,
			closing: $message->advice,
		);
	}

	/**
	 * A user agent as users are shown it: control characters removed, cut short.
	 */
	public static function shortUserAgent(?string $userAgent): ?string {
		if ($userAgent === null) {
			return null;
		}
		$clean = trim((string)(preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $userAgent) ?? ''));
		if ($clean === '') {
			return null;
		}
		return mb_strlen($clean) > self::MAX_USER_AGENT ? mb_substr($clean, 0, self::MAX_USER_AGENT - 1) . '…' : $clean;
	}

	/**
	 * The name a user gave an app password, as users are shown it: printable
	 * characters only, at most MAX_APP_PASSWORD_NAME of them, and nothing
	 * that a mail client could turn into a link (no "://", no "www.", no dot
	 * between a name and a top-level domain). Null when nothing is left.
	 */
	public static function appPasswordName(?string $name): ?string {
		$name = (string)$name;
		// Control, format (bidi overrides), private-use and unassigned characters.
		$name = (string)(preg_replace('/\p{C}+/u', ' ', $name) ?? '');
		$name = str_replace(['"', '://', '@'], ["'", ' ', ' '], $name);
		$name = (string)(preg_replace('/\bwww\s*[.。．｡]\s*/iu', '', $name) ?? '');
		$name = (string)(preg_replace('/(?<=[\p{L}\p{N}])\s*[.。．｡]\s*(?=\p{L}{2})/u', ' ', $name) ?? '');
		$name = trim((string)(preg_replace('/\s+/u', ' ', $name) ?? ''));
		if ($name === '') {
			return null;
		}
		return mb_strlen($name) > self::MAX_APP_PASSWORD_NAME ? rtrim(mb_substr($name, 0, self::MAX_APP_PASSWORD_NAME - 1)) . '…' : $name;
	}

	/**
	 * An app password as users are shown it: its name quoted, with the
	 * device its name stands for where there is one, e.g. "Thunderbird" or
	 * "Desktop" (Firefox on Windows). Null when neither is known.
	 */
	public static function appPassword(?string $name, IL10N $l): ?string {
		$shown = self::appPasswordName($name);
		$device = DeviceLabel::describe($name, $l);
		return match (true) {
			$shown !== null && $device !== null => $l->t('"%1$s" (%2$s)', [$shown, $device]),
			$shown !== null => $l->t('"%s"', [$shown]),
			$device !== null => $l->t('(%s)', [$device]),
			default => null,
		};
	}

	private function notice(Detection $detection, IL10N $l): UserNotice {
		try {
			$check = $this->container->get($this->registry->classOf($detection->getCheckId()));
		} catch (InvalidParamException) {
			$check = null;
		}
		if ($check instanceof IExplainsToUser) {
			return $check->userNotice($detection, $l);
		}
		return new UserNotice($l->t('Unusual activity on your account'), [$l->t('Nextcloud noticed unusual activity on your account.')]);
	}

	private function when(Detection $detection, IUser $user, IL10N $l): string {
		$time = $this->dates->dateTimeFor($detection->getCreatedAt(), $this->timeZoneOf($user), $l);
		$ip = $detection->getIp();
		$userAgent = $detection->getExplanationData()['userAgent'] ?? null;
		$device = DeviceLabel::describe(is_string($userAgent) ? $userAgent : null, $l);
		if ($ip === null) {
			return $l->t('This happened on %s.', [$time]);
		}
		if ($device === null) {
			return $l->t('This happened on %1$s, from the address %2$s.', [$time, $ip]);
		}
		return $l->t('This happened on %1$s, from the address %2$s. Device: %3$s.', [$time, $ip, $device]);
	}

	/**
	 * The user's own time zone setting, else the server's default. The time
	 * zone of the browser that made the request is not used: it may be the
	 * attacker's.
	 */
	public function timeZoneOf(IUser $user): \DateTimeZone {
		$name = $this->userConfig->getValueString($user->getUID(), 'core', 'timezone');
		if ($name !== '') {
			try {
				return new \DateTimeZone($name);
			} catch (\Exception) {
				// Fall back to the default below.
			}
		}
		return $this->dateTimeZone->getDefaultTimeZone();
	}

	/**
	 * What Nextcloud did, in the user's words. Only enforced actions count.
	 *
	 * @return list<string>
	 */
	private function done(Detection $detection, IL10N $l): array {
		$sentences = [];
		foreach ($detection->getActionList() as $action) {
			if (!$action['enforced']) {
				continue;
			}
			$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
			array_push($sentences, ...match ($action['type']) {
				ResponseType::Ban->value => $this->banSentences($ref, $l),
				ResponseType::KillSession->value => $this->killSentences($ref, $l),
				ResponseType::RevokeToken->value => $this->revokeSentences($ref, $l),
				ResponseType::ForcePasswordChange->value => match ($ref['state'] ?? null) {
					PasswordChangeService::STATE_REQUIRED => [$l->t('You will be asked to choose a new password the next time you log in.')],
					PasswordChangeService::STATE_EXTERNAL => [$l->t('Your password is managed outside Nextcloud, so your administrator was asked to reset it.')],
					default => [],
				},
				ResponseType::NotifyAdmin->value => (int)($ref['recipients'] ?? 0) > 0 ? [$l->t('Your administrators were told.')] : [],
				default => [],
			});
		}
		return $sentences;
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function banSentences(array $ref, IL10N $l): array {
		$cidrs = [];
		foreach ((array)($ref['bans'] ?? []) as $ban) {
			if (is_array($ban) && is_string($ban['cidr'] ?? null)) {
				$cidrs[] = $ban['cidr'];
			}
		}
		if ($cidrs === []) {
			return [];
		}
		$cidrs = array_slice(array_values(array_unique($cidrs)), 0, self::MAX_ADDRESSES);
		return [$l->n('The address %s was blocked.', 'The addresses %s were blocked.', count($cidrs), [implode(', ', $cidrs)])];
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function killSentences(array $ref, IL10N $l): array {
		$sentences = [];
		if (is_array($ref['session'] ?? null)) {
			$sentences[] = $l->t('The suspicious session was ended.');
		}
		$tokens = count((array)($ref['tokens'] ?? []));
		if ($tokens > 0) {
			$sentences[] = $l->n(
				'%n app password that came with it was revoked.',
				'%n app passwords that came with it were revoked.',
				$tokens,
			);
		}
		return $sentences;
	}

	/**
	 * @param array<array-key, mixed> $ref
	 * @return list<string>
	 */
	private function revokeSentences(array $ref, IL10N $l): array {
		$sentences = [];
		if (is_array($ref['token'] ?? null)) {
			$name = $ref['token']['name'] ?? null;
			$name = is_string($name) ? $name : null;
			if (($ref['session'] ?? false) === true) {
				// A browser session is named after its user agent, which is not the user's.
				$device = DeviceLabel::describe($name, $l);
				$sentences[] = $device === null ? $l->t('The session was ended.') : $l->t('The session (%s) was ended.', [$device]);
			} else {
				$appPassword = self::appPassword($name, $l);
				$sentences[] = $appPassword === null ? $l->t('The app password was revoked.') : $l->t('The app password %s was revoked.', [$appPassword]);
			}
		}
		$tokens = count((array)($ref['tokens'] ?? []));
		if ($tokens > 0) {
			$sentences[] = $l->n(
				'%n app password created with it was revoked as well.',
				'%n app passwords created with it were revoked as well.',
				$tokens,
			);
		}
		return $sentences;
	}
}
