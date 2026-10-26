<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCP\IL10N;

/**
 * Kinds of data an incident may have touched, for the "data categories"
 * of a breach notification. The report lists a category only when an
 * entry on the timeline points to it.
 */
enum DataCategory: string {
	/** Signs that someone else may have been in the account */
	case AccountContent = 'account_content';
	/** App passwords were created: they reach the account's data without the password */
	case ConnectedDevices = 'connected_devices';
	/** Files and folders shared in the period, and their recipients */
	case SharedFiles = 'shared_files';
	/** Administration rights, settings and other accounts */
	case Administration = 'administration';
	/** Which login names or email addresses exist on the server */
	case AccountExistence = 'account_existence';
	/** Names and email addresses of other users, from the user directory */
	case UserDirectory = 'user_directory';

	/**
	 * The categories detections of a check point to. Checks that only see
	 * failed attempts point to none: nothing was opened.
	 *
	 * @return list<self>
	 */
	public static function forCheck(string $checkId): array {
		return match ($checkId) {
			// The password was right, or a device was connected, or a credential was used elsewhere.
			'second_factor_failed', 'breached_password', 'login_flow_mismatch', 'token_concurrent_use', 'account_takeover', 'risky_network', 'new_login' => [self::AccountContent],
			'admin_change' => [self::Administration],
			'reset_probing', 'reserved_name' => [self::AccountExistence],
			'directory_scraping' => [self::UserDirectory],
			'share_bruteforce' => [self::SharedFiles],
			default => [],
		};
	}

	public function label(IL10N $l): string {
		return match ($this) {
			self::AccountContent => $l->t('The content of the account: files, calendars, contacts and everything else it can open'),
			self::ConnectedDevices => $l->t('Everything that can be reached with the app passwords created in this period'),
			self::SharedFiles => $l->t('Shared files and folders, and the people or links that received them'),
			self::Administration => $l->t('Administration rights, server settings and other accounts'),
			self::AccountExistence => $l->t('Which login names and email addresses exist on this server'),
			self::UserDirectory => $l->t('Names and email addresses of other users'),
		};
	}
}
