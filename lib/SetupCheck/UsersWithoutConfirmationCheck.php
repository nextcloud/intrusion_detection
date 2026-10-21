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
 * Setup check 9: active accounts with neither a second factor nor an email
 * address. If a check asks them to confirm a login, nothing can, and the
 * "no method" login confirmation settings decide. Information, or a
 * warning above {@see ConfirmationCoverage::WARNING_SHARE} of the active
 * accounts. Counted cheaply and cached for an hour.
 */
class UsersWithoutConfirmationCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly ConfirmationCoverage $coverage,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Accounts that cannot confirm a login');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Every active account has an email address or a second factor.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		['withoutMethod' => $without, 'active' => $active] = $this->coverage->users();
		if ($without === 0) {
			return null;
		}
		$warning = $active > 0 && $without / $active > ConfirmationCoverage::WARNING_SHARE;
		return new Finding(
			'users_without_confirmation',
			$warning ? Finding::LEVEL_WARNING : Finding::LEVEL_INFO,
			$l->n('%n account cannot confirm a login', '%n accounts cannot confirm a login', $without),
			$l->n(
				'%1$s of %2$s active accounts has neither a second factor nor an email address. If Nextcloud asks it to confirm a risky login, nothing can, and the login confirmation settings decide whether the login is refused.',
				'%1$s of %2$s active accounts have neither a second factor nor an email address. If Nextcloud asks them to confirm a risky login, nothing can, and the login confirmation settings decide whether the login is refused.',
				$without,
				[(string)$without, (string)$active],
			),
			$l->t('Ask these users to add an email address or set up a second factor. The login confirmation settings list them.'),
			'#settings-confirmation-accounts',
			$l->t('Show the accounts'),
		);
	}
}
