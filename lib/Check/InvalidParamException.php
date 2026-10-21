<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCP\IL10N;

/**
 * A setting value was rejected. Carries a machine-readable reason, so the admin
 * API, occ and the page can show the same translated message.
 */
final class InvalidParamException extends \InvalidArgumentException {
	/**
	 * @param array<string, scalar> $details
	 */
	public function __construct(
		public readonly string $reason,
		public readonly array $details = [],
	) {
		parent::__construct($reason . ($details === [] ? '' : ' ' . json_encode($details)));
	}

	public function describe(IL10N $l): string {
		$param = (string)($this->details['param'] ?? '');
		return match ($this->reason) {
			'not_an_integer' => $l->t('"%s" must be a whole number.', [$param]),
			'not_a_number' => $l->t('"%s" must be a number.', [$param]),
			'not_a_boolean' => $l->t('"%s" must be on or off.', [$param]),
			'not_a_duration' => $l->t('Use seconds, or a number with s, m, h or d, for example 10m.'),
			'too_small' => $l->t('"%1$s" must be at least %2$s.', [$param, (string)($this->details['min'] ?? '')]),
			'too_large' => $l->t('"%1$s" must be at most %2$s.', [$param, (string)($this->details['max'] ?? '')]),
			'not_a_choice' => $l->t('"%1$s" must be one of: %2$s.', [$param, (string)($this->details['choices'] ?? '')]),
			'not_a_list' => $l->t('"%s" must be a list.', [$param]),
			'too_many_items' => $l->t('"%1$s" can have at most %2$s entries.', [$param, (string)($this->details['max'] ?? '')]),
			'invalid_item' => $l->t('"%1$s" contains an invalid entry: %2$s', [$param, (string)($this->details['item'] ?? '')]),
			'invalid_range' => $l->t('"%1$s" contains an invalid address range: %2$s', [$param, (string)($this->details['item'] ?? '')]),
			'unknown_param' => $l->t('This check has no setting "%s".', [$param]),
			'unknown_check' => $l->t('There is no check "%s".', [(string)($this->details['check'] ?? '')]),
			'unknown_response' => $l->t('"%s" is not a response this check can use.', [(string)($this->details['response'] ?? '')]),
			'unknown_mode' => $l->t('The mode must be off, observe or protect.'),
			'mode_unavailable' => $l->t('This check cannot run on this server: %s', [(string)($this->details['why'] ?? '')]),
			'not_json' => $l->t('"%s" must be a valid JSON document.', [$param]),
			'unknown_list' => $l->t('There is no list "%s".', [(string)($this->details['list'] ?? '')]),
			'invalid_list_id' => $l->t('A list name must start with a letter and use only lower-case letters, digits and underscores, at most 32 characters.'),
			'list_needs_url' => $l->t('A new list needs an address and a purpose.'),
			'url_refused' => $l->t('Lists can only be downloaded from https:// addresses outside the local network, without a user name or password in the address.'),
			'builtin_list' => $l->t('The address, purpose and format of a built-in list cannot be changed, and it cannot be removed. Switch it off instead.'),
			'too_many_lists' => $l->t('There can be at most %s lists.', [(string)($this->details['max'] ?? '')]),
			'existing_user' => $l->t('"%s" is an existing account. Only names that no account uses can be reserved or used as decoys.', [(string)($this->details['item'] ?? '')]),
			'nextcloud_path' => $l->t('"%s" is, or covers, a path Nextcloud itself uses, so legitimate clients would be blocked.', [(string)($this->details['item'] ?? '')]),
			default => $l->t('The value is not valid.'),
		};
	}
}
