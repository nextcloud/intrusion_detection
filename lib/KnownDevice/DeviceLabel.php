<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

use OCP\IL10N;

/**
 * The browser and platform family of a user agent ("Firefox on Linux"), so
 * that users recognise their remembered devices. Plain substring tests in a
 * fixed order, no regular expressions: a user agent is attacker-controlled.
 * Only the first MAX_LENGTH characters are looked at.
 */
final class DeviceLabel {
	public const OTHER = 'other';
	public const MAX_LENGTH = 512;

	/** @var array<string, list<string>> family => markers, tested in this order */
	private const FAMILIES = [
		'nextcloud_desktop' => ['mirall/', 'nextcloud-desktop'],
		'nextcloud_android' => ['nextcloud-android'],
		'nextcloud_ios' => ['nextcloud-ios'],
		'edge' => ['edg/', 'edga/', 'edgios/'],
		'opera' => ['opr/', 'opera'],
		'firefox' => ['firefox/', 'fxios/'],
		'chrome' => ['chrome/', 'crios/', 'chromium/'],
		'safari' => ['safari/'],
	];

	/** @var array<string, list<string>> platform => markers, tested in this order */
	private const PLATFORMS = [
		'android' => ['android'],
		'ios' => ['iphone', 'ipad', 'ipod', 'ios'],
		'chromeos' => ['cros'],
		'windows' => ['windows'],
		'macos' => ['macintosh', 'mac os x', 'macos'],
		'linux' => ['linux', 'x11'],
	];

	/** @var array<string, string> */
	private const FAMILY_NAMES = [
		'nextcloud_desktop' => 'Nextcloud desktop client',
		'nextcloud_android' => 'Nextcloud Android app',
		'nextcloud_ios' => 'Nextcloud iOS app',
		'edge' => 'Edge',
		'opera' => 'Opera',
		'firefox' => 'Firefox',
		'chrome' => 'Chrome',
		'safari' => 'Safari',
	];

	/** @var array<string, string> */
	private const PLATFORM_NAMES = [
		'android' => 'Android',
		'ios' => 'iOS',
		'chromeos' => 'ChromeOS',
		'windows' => 'Windows',
		'macos' => 'macOS',
		'linux' => 'Linux',
	];

	/**
	 * @return array{0: string, 1: string} the browser and the platform family
	 */
	public static function parse(?string $userAgent): array {
		$agent = strtolower(substr((string)$userAgent, 0, self::MAX_LENGTH));
		return [self::first($agent, self::FAMILIES), self::first($agent, self::PLATFORMS)];
	}

	/**
	 * "Firefox on Linux", untranslated.
	 */
	public static function english(string $family, string $platform): string {
		$browser = self::FAMILY_NAMES[$family] ?? 'Unknown browser';
		$system = self::PLATFORM_NAMES[$platform] ?? null;
		return $system === null ? $browser : $browser . ' on ' . $system;
	}

	public static function translated(string $family, string $platform, IL10N $l): string {
		$browser = self::FAMILY_NAMES[$family] ?? $l->t('Unknown browser');
		$system = self::PLATFORM_NAMES[$platform] ?? null;
		return $system === null ? $browser : $l->t('%1$s on %2$s', [$browser, $system]);
	}

	/**
	 * The device a user agent or session name stands for, as users are
	 * shown it ("Firefox on Windows"), or null when neither the browser nor
	 * the system is known. Never the text itself: whoever sent it chose it.
	 */
	public static function describe(?string $userAgent, IL10N $l): ?string {
		[$family, $platform] = self::parse($userAgent);
		return $family === self::OTHER && $platform === self::OTHER ? null : self::translated($family, $platform, $l);
	}

	/**
	 * @param array<string, list<string>> $markers
	 */
	private static function first(string $agent, array $markers): string {
		foreach ($markers as $id => $needles) {
			foreach ($needles as $needle) {
				if (str_contains($agent, $needle)) {
					return $id;
				}
			}
		}
		return self::OTHER;
	}
}
