<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

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
		if (count($admins['withNeither']) === $total) {
			return new Finding(
				'admin_contact',
				Finding::LEVEL_ERROR,
				$l->t('No administrator can be reached or confirmed'),
				$l->t('No administrator has an email address or a second factor. Security alerts can only be seen inside Nextcloud, where an intruder in an administrator account sees them too, and a stolen password is enough to take over the server.'),
				$fix,
				'#confirmation',
				$l->t('Open the Confirmation tab'),
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
		return new Finding(
			'admin_contact',
			Finding::LEVEL_WARNING,
			$l->t('Administrators without email or second factor'),
			implode(' ', $problems),
			$fix,
			'#confirmation',
			$l->t('Open the Confirmation tab'),
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
