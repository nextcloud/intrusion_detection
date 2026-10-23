<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCP\IConfig;
use OCP\IUser;
use OCP\Mail\IEmailValidator;

/**
 * Whether the app can reach an account by email: the one answer for the
 * alerts, the digest, the coverage report and the email codes.
 */
class MailReach {
	public function __construct(
		private readonly IEmailValidator $emailValidator,
		private readonly IConfig $config,
	) {
	}

	/**
	 * Whether the account has a valid email address.
	 */
	public function hasAddress(IUser $user): bool {
		$address = (string)$user->getEMailAddress();
		return $address !== '' && $this->emailValidator->isValid($address);
	}

	/**
	 * Whether an email to the account is handed to a mail server: it has a
	 * valid address, and the server does not drop mail (`mail_smtpmode`
	 * `null`).
	 */
	public function canReach(IUser $user): bool {
		return $this->hasAddress($user) && $this->sendsMail();
	}

	/**
	 * Whether the server hands mail on at all.
	 */
	public function sendsMail(): bool {
		return $this->config->getSystemValueString('mail_smtpmode', 'smtp') !== 'null';
	}
}
