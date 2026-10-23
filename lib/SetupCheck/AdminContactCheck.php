<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;

/**
 * Setup check 10: administrators need an email address, so alerts reach them
 * outside Nextcloud, and a second factor, so a stolen password alone does
 * not give an intruder the server. Without either, an administrator's own
 * risky login cannot be confirmed either.
 *
 * - error: no administrator has an email address or a second factor;
 * - warning: some administrators lack one of them, or none has an email address;
 * - fine otherwise.
 *
 * While administrators log in from the trusted networks only, the
 * administrators with neither are named: their logins from elsewhere
 * cannot be confirmed with a code or a second factor.
 *
 * The administrators are checked through {@see ConfirmationCoverage}, which
 * caches the result for an hour.
 */
class AdminContactCheck extends ProblemCheck {
	/** At most this many names are listed */
	private const MAX_NAMES = 10;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly ConfirmationCoverage $coverage,
		private readonly AppSettings $settings,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Email and second factor of administrators');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Every administrator has an email address and a second factor.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$admins = $this->coverage->admins();
		$total = $admins['total'];
		$withoutEmail = $admins['withoutEmail'];
		$withoutSecondFactor = $admins['withoutSecondFactor'];
		if ($total === 0 || ($withoutEmail === [] && $withoutSecondFactor === [])) {
			return null;
		}
		$fix = $l->t('Add an email address and set up a second factor for every administrator, in their personal settings.');
		$outside = $this->outsideNetworks($admins['withNeither'], $l);
		if (count($admins['withNeither']) === $total) {
			return new Finding(
				'admin_contact',
				Finding::LEVEL_ERROR,
				$l->t('No administrator can be reached or confirmed'),
				implode(' ', array_filter([$l->t('No administrator has an email address or a second factor. Security alerts can only be seen inside Nextcloud, where an intruder in an administrator account sees them too, and a stolen password is enough to take over the server.'), $outside])),
				$fix,
				'#settings-confirmation',
				$l->t('Open the login confirmation settings'),
			);
		}

		$problems = [];
		if (count($withoutEmail) === $total) {
			$problems[] = $l->t('No administrator has an email address, so security alerts can only be seen inside Nextcloud, where an intruder in an administrator account sees them too.');
		} elseif ($withoutEmail !== []) {
			$problems[] = $l->n(
				'%n administrator has no email address and gets security alerts only inside Nextcloud: %s.',
				'%n administrators have no email address and get security alerts only inside Nextcloud: %s.',
				count($withoutEmail),
				[$this->names($withoutEmail, $l)],
			);
		}
		if ($withoutSecondFactor !== []) {
			$problems[] = $l->n(
				'%n administrator has no second factor, so the password alone opens the account: %s.',
				'%n administrators have no second factor, so the password alone opens their accounts: %s.',
				count($withoutSecondFactor),
				[$this->names($withoutSecondFactor, $l)],
			);
		}
		if ($outside !== null) {
			$problems[] = $outside;
		}
		return new Finding(
			'admin_contact',
			Finding::LEVEL_WARNING,
			$l->t('Administrators without email or second factor'),
			implode(' ', $problems),
			$fix,
			'#settings-confirmation',
			$l->t('Open the login confirmation settings'),
		);
	}

	/**
	 * The sentence naming the administrators who cannot confirm a login from
	 * outside the trusted networks, or null.
	 *
	 * @param list<string> $withNeither
	 */
	private function outsideNetworks(array $withNeither, IL10N $l): ?string {
		if ($withNeither === [] || !$this->settings->adminTrustedNetworksOnly()) {
			return null;
		}
		return $l->n(
			'Administrators log in from trusted networks only, but %n administrator has neither an email address nor a second factor to confirm a login from anywhere else: %s.',
			'Administrators log in from trusted networks only, but %n administrators have neither an email address nor a second factor to confirm a login from anywhere else: %s.',
			count($withNeither),
			[$this->names($withNeither, $l)],
		);
	}

	/**
	 * @param list<string> $uids
	 */
	private function names(array $uids, IL10N $l): string {
		$shown = array_slice($uids, 0, self::MAX_NAMES);
		$text = implode(', ', $shown);
		return count($uids) > count($shown) ? $l->t('%1$s and %2$s more', [$text, (string)(count($uids) - count($shown))]) : $text;
	}
}
