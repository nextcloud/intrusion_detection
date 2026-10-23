<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

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
			'zero_or_at_least' => $l->t('"%1$s" must be 0 (off) or at least %2$s.', [$param, (string)($this->details['min'] ?? '')]),
			'too_large' => $l->t('"%1$s" must be at most %2$s.', [$param, (string)($this->details['max'] ?? '')]),
			'not_a_choice' => $l->t('"%1$s" must be one of: %2$s.', [$param, (string)($this->details['choices'] ?? '')]),
			'not_a_list' => $l->t('"%s" must be a list.', [$param]),
			'too_many_items' => $l->t('"%1$s" can have at most %2$s entries.', [$param, (string)($this->details['max'] ?? '')]),
			'invalid_item' => $l->t('"%1$s" contains an invalid entry: %2$s', [$param, (string)($this->details['item'] ?? '')]),
			'invalid_pattern' => $l->t('"%1$s" contains a pattern that cannot be used: %2$s. %3$s', [$param, (string)($this->details['item'] ?? ''), match ($this->details['why'] ?? '') {
				'does_not_compile' => $l->t('It is not a valid regular expression.'),
				'matches_everything' => $l->t('It matches every value, even an empty one.'),
				'too_slow' => $l->t('It is too slow on long input and could be used to overload the server.'),
				'too_long' => $l->t('It is too long.'),
				default => '',
			}]),
			'invalid_range' => $l->t('"%1$s" contains an invalid address range: %2$s', [$param, (string)($this->details['item'] ?? '')]),
			'unknown_param' => $l->t('This check has no setting "%s".', [$param]),
			'unknown_check' => $l->t('There is no check "%s".', [(string)($this->details['check'] ?? '')]),
			'unknown_response' => $l->t('"%s" is not a response this check can use.', [(string)($this->details['response'] ?? '')]),
			'unknown_mode' => $l->t('The mode must be off, observe or protect.'),
			'mode_unavailable' => $l->t('This check cannot run on this server: %s', [Requirement::tryFrom((string)($this->details['why'] ?? ''))?->describe($l) ?? (string)($this->details['why'] ?? '')]),
			'not_json' => $l->t('"%s" must be a valid JSON document.', [$param]),
			'unknown_list' => $l->t('There is no list "%s".', [(string)($this->details['list'] ?? '')]),
			'invalid_list_id' => $l->t('A list name must start with a letter and use only lower-case letters, digits and underscores, at most 32 characters.'),
			'list_needs_url' => $l->t('A new list needs an address and a purpose.'),
			'url_refused' => $l->t('Lists can only be downloaded from https:// addresses outside the local network, without a user name or password in the address.'),
			'builtin_list' => $l->t('The address, purpose, format and checksum of a built-in list cannot be changed, and it cannot be removed. Switch it off instead.'),
			'invalid_sha256' => $l->t('A SHA-256 checksum has 64 hexadecimal characters.'),
			'too_many_lists' => $l->t('There can be at most %s lists.', [(string)($this->details['max'] ?? '')]),
			'existing_user' => $l->t('"%s" is an existing account. Only names that no account uses can be reserved or used as decoys.', [(string)($this->details['item'] ?? '')]),
			'locked' => $l->t('This setting is locked in config.php ("intrusion_detection.locked"), so it cannot be changed here or with occ.'),
			'too_few_admins' => $l->t('A second administrator must exist who can approve. Add another administrator first.'),
			'nextcloud_path' => $l->t('"%s" is, or covers, a path Nextcloud itself uses, so legitimate clients would be blocked.', [(string)($this->details['item'] ?? '')]),
			default => $l->t('The value is not valid.'),
		};
	}
}
