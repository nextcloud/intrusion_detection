<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory;

use OCA\IntrusionDetection\KnownDevice\DeviceLabel;

/**
 * What an account's own login history says about one of its logins, or
 * about a security event, compared with the account's logins of the WINDOW
 * before it that went through (needed nothing, or were confirmed):
 *
 * - "your usual network": a trusted network of the account, or the network
 *   of such a login; "new network": neither, while there were such logins;
 * - "new device": no remembered device, and none of those logins came from
 *   the same kind of device (browser and system, as {@see DeviceLabel} names
 *   them); never for a user agent that names neither;
 * - "unusual hour": a login of a person (the login form, single sign-on or
 *   a browser that stayed logged in) at a time of day in the user's time
 *   zone more than HOUR_SPREAD hours away from each of at least
 *   MIN_HOUR_BASELINE such logins before it. App logins have no hour.
 *
 * Nothing new is claimed where the history cannot tell: before the first
 * login that went through, and where the logins given do not cover the
 * whole WINDOW; there only the usual network is said. Built from rows the
 * page reads anyway; it stores nothing.
 */
final class SignInHabits {
	public const USUAL_NETWORK = 'usual_network';
	public const NEW_NETWORK = 'new_network';
	public const NEW_DEVICE = 'new_device';
	public const UNUSUAL_HOUR = 'unusual_hour';
	/** A user agent that names neither a known browser nor a system: no device to compare */
	public const UNKNOWN_KIND = DeviceLabel::OTHER . '/' . DeviceLabel::OTHER;

	/** Earlier logins this recent count, as for a familiar place */
	public const WINDOW = 30 * 86400;
	/** An hour can be unusual only after this many earlier logins of a person */
	public const MIN_HOUR_BASELINE = 5;
	/** Hours of the day this close to an earlier login are usual */
	public const HOUR_SPREAD = 1;
	/** A kind of device is the usual one after this many logins of a person with it */
	public const MIN_USUAL_DEVICE = 3;
	/** The logins of a person, whose time of day and device say something about a habit */
	public const PERSONAL_METHODS = [LoginHistory::METHOD_PASSWORD, LoginHistory::METHOD_SSO, LoginHistory::METHOD_COOKIE];

	/** @var list<array{at: int, net: ?string, kind: string, personal: bool, hour: int}> */
	private array $through = [];
	/** @var array<string, true> */
	private array $trusted;

	/**
	 * @param list<LoginHistoryEntry> $logins the account's logins, in any order
	 * @param list<string> $trustedNetworks the account's trusted networks
	 * @param int $completeSince the logins given are all of the account's since this time
	 */
	public function __construct(
		array $logins,
		array $trustedNetworks,
		private readonly \DateTimeZone $timeZone,
		private readonly int $completeSince,
	) {
		foreach ($logins as $login) {
			if (self::wentThrough($login)) {
				$this->through[] = [
					'at' => $login->createdAt,
					'net' => $login->netKey,
					'kind' => self::kind($login->userAgent),
					'personal' => in_array($login->method, self::PERSONAL_METHODS, true),
					'hour' => $this->minuteOfDay($login->createdAt),
				];
			}
		}
		$this->trusted = array_fill_keys($trustedNetworks, true);
	}

	/**
	 * Whether a login went through: it needed nothing, or it was confirmed.
	 */
	public static function wentThrough(LoginHistoryEntry $login): bool {
		return $login->stepUp === null || $login->stepUp === LoginHistory::STEP_UP_CONFIRMED;
	}

	/**
	 * The kind of device a user agent stands for: its browser and system.
	 */
	public static function kind(?string $userAgent): string {
		[$family, $platform] = DeviceLabel::parse($userAgent);
		return $family . '/' . $platform;
	}

	/**
	 * The labels of one of the account's logins.
	 *
	 * @return list<'usual_network'|'new_network'|'new_device'|'unusual_hour'>
	 */
	public function forLogin(LoginHistoryEntry $login): array {
		return $this->labels($login->createdAt, $login->netKey, $login->userAgent, $login->knownDevice, in_array($login->method, self::PERSONAL_METHODS, true));
	}

	/**
	 * The labels of an event at a time, from a network and a device.
	 *
	 * @param bool $personal a login of a person, whose hour says something
	 * @param int $ownLogin seconds before the event whose logins are left out, as the event's own
	 * @return list<'usual_network'|'new_network'|'new_device'|'unusual_hour'>
	 */
	public function labels(int $at, ?string $netKey, ?string $userAgent, bool $knownDevice, bool $personal, int $ownLogin = 0): array {
		$earlier = $this->before($at, $ownLogin);
		$usual = $netKey !== null && (isset($this->trusted[$netKey]) || in_array($netKey, array_column($earlier, 'net'), true));
		if ($at - self::WINDOW < $this->completeSince) {
			return $usual ? [self::USUAL_NETWORK] : [];
		}
		$labels = [];
		if ($usual) {
			$labels[] = self::USUAL_NETWORK;
		} elseif ($netKey !== null && $earlier !== []) {
			$labels[] = self::NEW_NETWORK;
		}
		$kind = self::kind($userAgent);
		if (!$knownDevice && $earlier !== [] && $kind !== self::UNKNOWN_KIND && !in_array($kind, array_column($earlier, 'kind'), true)) {
			$labels[] = self::NEW_DEVICE;
		}
		if ($personal && $this->unusualHour($at, $earlier)) {
			$labels[] = self::UNUSUAL_HOUR;
		}
		return $labels;
	}

	/**
	 * The known kind of device most of the person's logins in the WINDOW
	 * before a time came from, when at least MIN_USUAL_DEVICE did, and how
	 * many networks the account trusts or such logins came from.
	 *
	 * @param int $ownLogin seconds before the time whose logins are left out, as the event's own
	 * @return ?array{family: string, platform: string, networks: int} the browser and system as {@see DeviceLabel::parse()} gives them
	 */
	public function usual(int $at, int $ownLogin = 0): ?array {
		if ($at - self::WINDOW < $this->completeSince) {
			return null;
		}
		$earlier = $this->before($at, $ownLogin);
		$kinds = [];
		foreach ($earlier as $login) {
			if ($login['personal'] && $login['kind'] !== self::UNKNOWN_KIND) {
				$kinds[] = $login['kind'];
			}
		}
		$counts = array_count_values($kinds);
		arsort($counts);
		$kind = (string)array_key_first($counts);
		if ($kind === '' || $counts[$kind] < self::MIN_USUAL_DEVICE) {
			return null;
		}
		[$family, $platform] = explode('/', $kind, 2);
		$networks = array_filter(array_column($earlier, 'net'), 'is_string');
		return ['family' => $family, 'platform' => $platform, 'networks' => count(array_unique([...$networks, ...array_keys($this->trusted)]))];
	}

	/**
	 * The logins that went through in the WINDOW before a time. Logins in
	 * the same second, or the given seconds before it, are left out: an
	 * event's own login is no habit.
	 *
	 * @return list<array{at: int, net: ?string, kind: string, personal: bool, hour: int}>
	 */
	private function before(int $at, int $ownLogin = 0): array {
		$until = $at - max(0, $ownLogin);
		return array_values(array_filter(
			$this->through,
			static fn (array $login): bool => $login['at'] < $until && $login['at'] >= $at - self::WINDOW,
		));
	}

	/**
	 * @param list<array{at: int, net: ?string, kind: string, personal: bool, hour: int}> $earlier
	 */
	private function unusualHour(int $at, array $earlier): bool {
		$minutes = array_column(array_filter($earlier, static fn (array $login): bool => $login['personal']), 'hour');
		if (count($minutes) < self::MIN_HOUR_BASELINE) {
			return false;
		}
		$now = $this->minuteOfDay($at);
		foreach ($minutes as $minute) {
			$distance = abs($now - $minute);
			if (min($distance, 1440 - $distance) <= self::HOUR_SPREAD * 60) {
				return false;
			}
		}
		return true;
	}

	private function minuteOfDay(int $at): int {
		$time = (new \DateTimeImmutable('@' . $at))->setTimezone($this->timeZone);
		return (int)$time->format('G') * 60 + (int)$time->format('i');
	}
}
