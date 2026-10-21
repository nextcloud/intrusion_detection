<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

/**
 * A session-state rule's answer that a request may not proceed.
 *
 * Browsers navigating to a page are sent to `$redirectUrl` when there is
 * one. Other AppFramework and OCS requests get 403 with
 * `{"error": $error}`, WebDAV requests 403 with the header `$davHeader:
 * required`.
 *
 * A rate limit ({@see self::rateLimited()}) answers 429 with `Retry-After`
 * instead, on every kind of request.
 *
 * Blocks with `$data` add it to the JSON and OCS answers, and also send
 * browsers that submit a form to `$redirectUrl`: a sensitive action that
 * needs a confirmation ({@see self::confirmationRequired()}) answers
 * `403 {"error": "confirmation_required", "url": …}`.
 */
final class SessionBlock {
	public const CONFIRMATION_REQUIRED = 'confirmation_required';
	public const CONFIRMATION_HEADER = 'X-Nextcloud-Confirmation';
	public function __construct(
		/** Machine-readable, e.g. "password_change_required" */
		public readonly string $error,
		/** The header that tells WebDAV clients why, e.g. "X-Nextcloud-Password-Change"; empty for a rate limit */
		public readonly string $davHeader,
		/** A short English sentence for WebDAV error bodies */
		public readonly string $message,
		/** Where a browser is sent to resolve the state; null to answer 403 there too */
		public readonly ?string $redirectUrl = null,
		/** Seconds until the request may be repeated; set for a rate limit only */
		public readonly ?int $retryAfter = null,
		/** @var array<string, string|array<string, string>> more for the JSON and OCS answers, such as the URL that resolves the block */
		public readonly array $data = [],
	) {
	}

	/**
	 * A sensitive action in a session that must confirm it first: 403 with
	 * the URL of the confirm page, which returns to the page the user was on.
	 *
	 * @param array<string, string> $dialog the texts of the dialog that asks for it, in the user's language
	 */
	public static function confirmationRequired(string $url, string $message, array $dialog): self {
		return new self(
			self::CONFIRMATION_REQUIRED,
			self::CONFIRMATION_HEADER,
			'This action needs a fresh confirmation. Confirm it in a browser, then try again.',
			$url,
			null,
			['url' => $url, 'message' => $message, 'dialog' => $dialog],
		);
	}

	/**
	 * A request that is refused outright, with a message for the user and,
	 * for browsers, a page that explains it.
	 */
	public static function refused(string $error, string $davHeader, string $message, ?string $pageUrl): self {
		return new self($error, $davHeader, $message, $pageUrl, null, ['message' => $message]);
	}

	/**
	 * The request is one too many of its kind: 429 until `$retryAfter` seconds have passed.
	 */
	public static function rateLimited(string $error, string $message, int $retryAfter): self {
		return new self($error, '', $message, null, max(1, $retryAfter));
	}

	public function isRateLimit(): bool {
		return $this->retryAfter !== null;
	}
}
