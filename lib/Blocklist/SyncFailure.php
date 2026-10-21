<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * Why a list was not taken. The code is stored and shown to the administrator.
 */
class SyncFailure extends \RuntimeException {
	/** The address is not https, carries credentials, or points into the local network */
	public const URL_REFUSED = 'url_refused';
	/** No connection, a timeout, or a redirect to a refused address */
	public const NETWORK = 'network_error';
	/** The server answered with a status other than 200 or 304 */
	public const HTTP = 'http_error';
	/** The answer is larger than the download limit */
	public const TOO_LARGE = 'too_large';
	/** The file is not in the list's format */
	public const INVALID_FORMAT = 'invalid_format';
	/** The file has no ranges at all */
	public const EMPTY = 'empty';
	/** More entries than blocklist_max_entries */
	public const TOO_MANY_ENTRIES = 'too_many_entries';
	/** More than 1 % of the entries are not ranges */
	public const TOO_MANY_MALFORMED = 'too_many_malformed';

	public function __construct(
		public readonly string $reason,
		string $detail = '',
	) {
		parent::__construct($detail !== '' ? $reason . ': ' . $detail : $reason);
	}
}
