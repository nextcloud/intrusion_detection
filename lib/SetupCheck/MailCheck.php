<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * No mail server is configured: alerts reach administrators only inside
 * Nextcloud, and nothing that needs an email can work.
 */
class MailCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly Prerequisites $prerequisites,
		private readonly IURLGenerator $urlGenerator,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: email');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Nextcloud can send emails.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if ($this->prerequisites->hasMail()) {
			return null;
		}
		return new Finding(
			'mail_missing',
			Finding::LEVEL_WARNING,
			$l->t('Nextcloud cannot send emails'),
			$l->t('No mail server is configured. Administrators get alerts only as notifications inside Nextcloud, and checks and responses that need email cannot run. Users cannot be asked to confirm a login with a code sent by email.'),
			$l->t('Set up email in Administration settings → Basic settings, and send a test email.'),
			$this->urlGenerator->linkToDocs('admin-email'),
			$l->t('Email documentation'),
		);
	}
}
