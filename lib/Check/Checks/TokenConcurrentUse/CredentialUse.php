<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

/**
 * What the credential guard noted about the current request, for the code
 * that runs after authentication ({@see CredentialUseResolver}). It holds
 * no secret and no credential key: the credential is read from the request
 * again when it is verified.
 */
final class CredentialUse {
	/** A switch that fired, waiting to be confirmed by a successful login */
	public ?CredentialSwitch $switch = null;
	/** The credential has no history yet: it gets one once it logged in */
	public bool $unknown = false;
	public bool $resolved = false;
	/** The account and login name of a login with a password (not a token) in this request */
	public ?string $passwordLoginUid = null;
	public ?string $passwordLoginName = null;

	/**
	 * @param PresentedCredential::SCHEME_* $scheme
	 */
	public function __construct(
		public readonly string $scheme,
		public readonly bool $hasSessionCookie,
	) {
	}

	/**
	 * Whether anything is left to do after authentication: a pending switch,
	 * a credential seen for the first time, or an Authorization header next
	 * to a session cookie, where it is only known after authentication which
	 * of the two logged the request in.
	 */
	public function needsResolution(): bool {
		return !$this->resolved
			&& ($this->switch !== null || $this->unknown || ($this->scheme !== PresentedCredential::SCHEME_SESSION && $this->hasSessionCookie));
	}
}
