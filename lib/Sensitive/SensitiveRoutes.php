<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCP\IL10N;
use OCP\Share\IShare;

/**
 * The actions that need a fresh confirmation in a risky session (concept
 * section 11.13), in groups an administrator switches on and off.
 *
 * Requests are matched by their route name, as the router names it (lower
 * case, `ocs.` for OCS routes), with one array lookup; a test boots the
 * router and fails when one of them no longer exists. Some routes change
 * many things, so their parameters decide whether the request is sensitive
 * (only an email or password change of the account edit, for example);
 * parameters are read only for those routes.
 */
final class SensitiveRoutes {
	/** The check id the notices about unconfirmed actions are counted under */
	public const CHECK_ID = 'sensitive_action';

	/** Email address, password and (optionally) display name */
	public const GROUP_ACCOUNT = 'account';
	/** Turning off a second factor, new backup codes */
	public const GROUP_SECOND_FACTOR = 'second_factor';
	/** New app passwords and connected devices */
	public const GROUP_DEVICES = 'devices';
	/** Public links and federated shares of the whole account or of large folders */
	public const GROUP_SHARING = 'sharing';
	/** New administrators and accounts, apps, security settings */
	public const GROUP_ADMIN = 'admin';
	public const GROUPS = [self::GROUP_ACCOUNT, self::GROUP_SECOND_FACTOR, self::GROUP_DEVICES, self::GROUP_SHARING, self::GROUP_ADMIN];
	public const GROUP_PATTERN = '/^(account|second_factor|devices|sharing|admin)$/';

	/** What a route's parameters must say for the request to be sensitive */
	public const RULE_ALWAYS = 'always';
	/** The account edit: email or password, or the display name when that is included */
	public const RULE_ACCOUNT_KEY = 'account_key';
	/** The account edit with several fields: email, password, display name, or the admin group */
	public const RULE_ACCOUNT_FIELDS = 'account_fields';
	/** The additional email addresses of an account */
	public const RULE_ADDITIONAL_MAIL = 'additional_mail';
	/** Changing a display name, when that is included */
	public const RULE_DISPLAY_NAME = 'display_name';
	/** Adding an account to the admin group */
	public const RULE_ADMIN_GROUP = 'admin_group';
	/** A public link or federated share; the size of what is shared decides ({@see ShareSize}) */
	public const RULE_SHARE = 'share';

	/** @var array<string, array{0: string, 1: string}> route name => group and rule */
	public const ROUTES = [
		'ocs.provisioning_api.users.edituser' => [self::GROUP_ACCOUNT, self::RULE_ACCOUNT_KEY],
		'ocs.provisioning_api.users.editusermultifield' => [self::GROUP_ACCOUNT, self::RULE_ACCOUNT_FIELDS],
		'ocs.provisioning_api.users.editusermultivalue' => [self::GROUP_ACCOUNT, self::RULE_ADDITIONAL_MAIL],
		'settings.changepassword.changepersonalpassword' => [self::GROUP_ACCOUNT, self::RULE_ALWAYS],
		'settings.changepassword.changeuserpassword' => [self::GROUP_ACCOUNT, self::RULE_ALWAYS],
		'settings.users.setemailaddress' => [self::GROUP_ACCOUNT, self::RULE_ALWAYS],
		'settings.users.setdisplayname' => [self::GROUP_ACCOUNT, self::RULE_DISPLAY_NAME],
		'ocs.core.twofactorapi.disable' => [self::GROUP_SECOND_FACTOR, self::RULE_ALWAYS],
		'twofactor_backupcodes.settings.createcodes' => [self::GROUP_SECOND_FACTOR, self::RULE_ALWAYS],
		'settings.authsettings.create' => [self::GROUP_DEVICES, self::RULE_ALWAYS],
		'ocs.core.apppassword.getapppassword' => [self::GROUP_DEVICES, self::RULE_ALWAYS],
		'ocs.core.apppassword.getapppasswordwithonetimepassword' => [self::GROUP_DEVICES, self::RULE_ALWAYS],
		'core.clientflowlogin.generateapppassword' => [self::GROUP_DEVICES, self::RULE_ALWAYS],
		'core.clientflowloginv2.generateapppassword' => [self::GROUP_DEVICES, self::RULE_ALWAYS],
		'ocs.files_sharing.shareapi.createshare' => [self::GROUP_SHARING, self::RULE_SHARE],
		'ocs.provisioning_api.users.addtogroup' => [self::GROUP_ADMIN, self::RULE_ADMIN_GROUP],
		'ocs.provisioning_api.users.adduser' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.provisioning_api.apps.enable' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.provisioning_api.apps.disable' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.appstore.api.enableapp' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.appstore.api.disableapp' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.provisioning_api.appconfig.setvalue' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.provisioning_api.appconfig.deletekey' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'settings.twofactorsettings.update' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.intrusion_detection.adminapi.updatesettings' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.intrusion_detection.adminapi.resetsettings' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.intrusion_detection.adminapi.updatecheck' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.intrusion_detection.adminapi.resetcheck' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
		'ocs.intrusion_detection.adminapi.updatelearning' => [self::GROUP_ADMIN, self::RULE_ALWAYS],
	];

	/** Keys of the account edit that change the email address or the password */
	public const ACCOUNT_KEYS = ['email', 'password'];
	/** Keys of the account edit that change the display name */
	public const DISPLAY_NAME_KEYS = ['display', 'displayname'];
	public const ADDITIONAL_MAIL = 'additional_mail';
	public const ADMIN_GROUP = 'admin';
	/** Share types that make files reachable from outside the server */
	public const OUTSIDE_SHARE_TYPES = [IShare::TYPE_LINK, IShare::TYPE_REMOTE, IShare::TYPE_REMOTE_GROUP];

	/**
	 * The group of a request, or null when it is not sensitive. Sharing
	 * requests are only sensitive for a large folder, which the caller
	 * decides with {@see ShareSize} ({@see self::needsShareCheck()}).
	 *
	 * @param \Closure(string): mixed $param reads a request parameter; asked only for routes whose parameters decide
	 */
	public static function group(mixed $route, \Closure $param, bool $includeDisplayName): ?string {
		if (!is_string($route) || !isset(self::ROUTES[$route])) {
			return null;
		}
		[$group, $rule] = self::ROUTES[$route];
		$sensitive = match ($rule) {
			self::RULE_ALWAYS, self::RULE_SHARE => true,
			self::RULE_ACCOUNT_KEY => in_array($param('key'), $includeDisplayName ? [...self::ACCOUNT_KEYS, ...self::DISPLAY_NAME_KEYS] : self::ACCOUNT_KEYS, true),
			self::RULE_ACCOUNT_FIELDS => self::accountFields($param, $includeDisplayName) !== null,
			self::RULE_ADDITIONAL_MAIL => $param('collectionName') === self::ADDITIONAL_MAIL,
			self::RULE_DISPLAY_NAME => $includeDisplayName,
			self::RULE_ADMIN_GROUP => $param('groupid') === self::ADMIN_GROUP,
		};
		if (!$sensitive) {
			return null;
		}
		return $rule === self::RULE_ACCOUNT_FIELDS ? self::accountFields($param, $includeDisplayName) : $group;
	}

	/**
	 * Whether the route is a share creation, whose type and size decide.
	 */
	public static function needsShareCheck(string $route): bool {
		return (self::ROUTES[$route][1] ?? null) === self::RULE_SHARE;
	}

	/**
	 * The share type of a share creation, when it reaches outside the server.
	 *
	 * @param \Closure(string): mixed $param
	 */
	public static function isOutsideShare(\Closure $param): bool {
		$type = $param('shareType');
		return is_numeric($type) && in_array((int)$type, self::OUTSIDE_SHARE_TYPES, true);
	}

	/**
	 * The group a request belongs to by its name, in the words of the admin page.
	 */
	public static function groupLabel(string $group, IL10N $l): string {
		return match ($group) {
			self::GROUP_ACCOUNT => $l->t('Account'),
			self::GROUP_SECOND_FACTOR => $l->t('Second factor'),
			self::GROUP_DEVICES => $l->t('Devices'),
			self::GROUP_SHARING => $l->t('Sharing'),
			self::GROUP_ADMIN => $l->t('Administration'),
			default => $group,
		};
	}

	/**
	 * What a group protects, with the settings it depends on as `{name}` placeholders.
	 *
	 * @return list<string>
	 */
	public static function groupExamples(string $group, IL10N $l): array {
		return match ($group) {
			self::GROUP_ACCOUNT => [
				$l->t('Changing an email address, also by an administrator'),
				$l->t('Changing a password, also by an administrator'),
				$l->t('Changing a display name, if you include it below'),
			],
			self::GROUP_SECOND_FACTOR => [
				$l->t('Turning off a second factor of an account'),
				$l->t('Generating new backup codes'),
			],
			self::GROUP_DEVICES => [
				$l->t('Creating an app password'),
				$l->t('Connecting a desktop or mobile client'),
			],
			self::GROUP_SHARING => [
				$l->t('A public link or federated share of a whole account\'s files'),
				$l->t('A public link or federated share of a folder with more than {sensitive_share_min_files} files'),
			],
			self::GROUP_ADMIN => [
				$l->t('Adding someone to the admin group, creating accounts'),
				$l->t('Enabling or disabling apps'),
				$l->t('Changing app settings directly, two-factor enforcement, and the settings of intrusion detection'),
			],
			default => [],
		};
	}

	/**
	 * The group of an account edit with several fields: the admin group
	 * comes first, as it is the larger risk.
	 *
	 * @param \Closure(string): mixed $param
	 */
	private static function accountFields(\Closure $param, bool $includeDisplayName): ?string {
		$groups = $param('groups');
		if (is_array($groups) && in_array(self::ADMIN_GROUP, $groups, true)) {
			return self::GROUP_ADMIN;
		}
		if ($param('email') !== null || $param('password') !== null || ($includeDisplayName && $param('displayName') !== null)) {
			return self::GROUP_ACCOUNT;
		}
		return null;
	}
}
