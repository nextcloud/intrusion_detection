<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCP\IL10N;

/**
 * A block or lift by hand was refused: the target is not an address or
 * network that can be blocked, is never blocked (loopback, this server, the
 * brute-force allowlist, also inside a network) or is the administrator's
 * own address, or the level, duration or note is out of range.
 */
final class InvalidBanException extends \InvalidArgumentException {
	/** Not an IPv4 address or /24, nor an IPv6 address or /64 */
	public const TARGET = 'target';
	/** This server or a loopback address */
	public const NEVER = 'never';
	/** On the brute-force allowlist */
	public const ALLOWLISTED = 'allowlisted';
	/** The address of the administrator who asks, or its network */
	public const OWN_ADDRESS = 'own_address';
	/** A network that contains an address that is never blocked */
	public const CONTAINS_NEVER = 'contains_never';
	public const LEVEL = 'level';
	public const DURATION = 'duration';
	public const NOTE_TOO_LONG = 'note_too_long';

	/**
	 * @param self::* $problem
	 * @param string $address the address or network the problem is about, if any
	 */
	public function __construct(
		public readonly string $problem,
		public readonly string $address = '',
	) {
		parent::__construct($problem . ($address === '' ? '' : ' ' . $address));
	}

	/**
	 * The field the problem is about.
	 */
	public function param(): string {
		return match ($this->problem) {
			self::LEVEL => 'level',
			self::DURATION => 'duration',
			self::NOTE_TOO_LONG => 'note',
			default => 'target',
		};
	}

	/**
	 * The machine-readable reason of the API.
	 */
	public function reason(): string {
		return match ($this->problem) {
			self::LEVEL => 'invalid_level',
			self::DURATION => 'invalid_duration',
			self::NOTE_TOO_LONG => 'too_long',
			default => 'invalid_target',
		};
	}

	public function describe(IL10N $l): string {
		return match ($this->problem) {
			self::NEVER => $l->t('%s is this server or a loopback address. It is never blocked.', [$this->address]),
			self::ALLOWLISTED => $l->t('%s is on the brute-force allowlist, so it is never blocked. Remove it from the allowlist first.', [$this->address]),
			self::OWN_ADDRESS => $l->t('This would block your own address (%s) and lock you out. If you really need it, use occ intrusion:bans:add.', [$this->address]),
			self::CONTAINS_NEVER => $l->t('%s contains this server, a loopback address or an address on the brute-force allowlist, so it is never blocked.', [$this->address]),
			self::LEVEL => $l->t('The level must be 1, 2 or 3.'),
			self::DURATION => $l->t('A block lasts from 5 minutes to 90 days.'),
			self::NOTE_TOO_LONG => $l->t('The note can have at most %s characters.', [(string)BanService::MAX_NOTE]),
			default => $l->t('Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.'),
		};
	}
}
