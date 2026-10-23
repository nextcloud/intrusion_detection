<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * No mail server is configured: alerts reach administrators only inside
 * Nextcloud, and nothing that needs an email can work.
 *
 * Or mail goes to an SMTP server on another host without enforced TLS.
 * Core then encrypts only when the server offers STARTTLS, so whoever can
 * strip that offer on the way reads the login codes and lock links, which
 * go by email. TLS is enforced with `mail_smtpsecure` = `ssl` or port 465;
 * `mail_smtpstreamoptions` that switch off certificate checks count as no
 * TLS.
 */
class MailCheck extends ProblemCheck {
	/** Hosts on this server, where mail never crosses a network */
	private const LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1', '[::1]'];
	/** The port of SMTP over TLS, where the mailer always speaks TLS */
	private const IMPLICIT_TLS_PORT = 465;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly Prerequisites $prerequisites,
		private readonly IURLGenerator $urlGenerator,
		private readonly IConfig $config,
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
			return $this->withoutTls() ? new Finding(
				'mail_without_tls',
				Finding::LEVEL_WARNING,
				$l->t('Emails to the mail server may go unencrypted'),
				$l->t('Nextcloud sends emails to a mail server on another host and uses TLS only when that server offers it. Someone on the way could remove that offer and read the login codes and lock links sent by email.'),
				$l->t('Set the encryption to SSL/TLS in Administration settings → Basic settings (port 465), or make sure the connection to the mail server cannot be tampered with.'),
				$this->urlGenerator->linkToDocs('admin-email'),
				$l->t('Email documentation'),
			) : null;
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

	/**
	 * Whether mail goes by SMTP to another host without enforced TLS.
	 */
	private function withoutTls(): bool {
		if ($this->config->getSystemValueString('mail_smtpmode', 'smtp') !== 'smtp') {
			return false;
		}
		$host = strtolower(trim($this->config->getSystemValueString('mail_smtphost', '127.0.0.1')));
		if (in_array($host, self::LOCAL_HOSTS, true)) {
			return false;
		}
		$options = $this->config->getSystemValue('mail_smtpstreamoptions', []);
		$ssl = is_array($options) && is_array($options['ssl'] ?? null) ? $options['ssl'] : [];
		if (($ssl['verify_peer'] ?? true) === false || ($ssl['allow_self_signed'] ?? false) === true) {
			return true;
		}
		return $this->config->getSystemValueString('mail_smtpsecure', '') !== 'ssl'
			&& $this->config->getSystemValueInt('mail_smtpport', 25) !== self::IMPLICIT_TLS_PORT;
	}
}
