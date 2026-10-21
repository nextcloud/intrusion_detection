<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

/**
 * The requests through which a logged-in account can read the user
 * directory, in groups with a limit each (concept section 10.16).
 *
 * AppFramework requests are matched by their route name, as the router
 * names it (lower case, `ocs.` for OCS routes), with one array lookup; a
 * test boots the router and fails when one of them no longer exists.
 * WebDAV requests are matched by method and path: the system address book
 * and searches in the principal collections.
 */
final class DirectoryRoutes {
	/** Searching for people: autocomplete, the sharing dialog, the contacts menu, unified search */
	public const GROUP_SEARCH = 'search';
	/** Profile pages and avatars of other accounts */
	public const GROUP_PROFILE = 'profile';
	/** The system address book and the user list over WebDAV */
	public const GROUP_ADDRESSBOOK = 'addressbook';
	/** The user lists of the provisioning API (administrators and group administrators) */
	public const GROUP_USERS = 'users';
	public const GROUPS = [self::GROUP_SEARCH, self::GROUP_PROFILE, self::GROUP_ADDRESSBOOK, self::GROUP_USERS];

	public const ROUTES = [
		'ocs.core.autocomplete.get' => self::GROUP_SEARCH,
		'ocs.files_sharing.shareesapi.search' => self::GROUP_SEARCH,
		'core.contactsmenu.index' => self::GROUP_SEARCH,
		'ocs.core.unifiedsearch.search' => self::GROUP_SEARCH,
		'ocs.provisioning_api.users.searchbyphonenumbers' => self::GROUP_SEARCH,
		'profile.profilepage.index' => self::GROUP_PROFILE,
		'ocs.core.profileapi.getprofilefields' => self::GROUP_PROFILE,
		'core.avatar.getavatar' => self::GROUP_PROFILE,
		'core.avatar.getavatardark' => self::GROUP_PROFILE,
		'ocs.provisioning_api.users.getusers' => self::GROUP_USERS,
		'ocs.provisioning_api.users.getusersdetails' => self::GROUP_USERS,
		'ocs.provisioning_api.users.getdisabledusersdetails' => self::GROUP_USERS,
		'ocs.provisioning_api.users.getlastloggedinusers' => self::GROUP_USERS,
		'ocs.provisioning_api.users.getuser' => self::GROUP_USERS,
		'ocs.provisioning_api.groups.getgroupusers' => self::GROUP_USERS,
		'ocs.provisioning_api.groups.getgroupusersdetails' => self::GROUP_USERS,
	];

	/** Unified search counts only with the providers that find people */
	public const UNIFIED_SEARCH_ROUTE = 'ocs.core.unifiedsearch.search';
	public const PEOPLE_PROVIDERS = ['users', 'contacts'];

	/** The system address book, as it appears in each account's address books */
	public const SYSTEM_ADDRESS_BOOK = 'z-server-generated--system';
	public const DAV_ROOT = '/remote.php/dav/';
	/** Principal collections whose listing or search reveals accounts */
	private const PRINCIPAL_COLLECTIONS = ['users', 'groups'];

	/**
	 * The group of an AppFramework request, or null for every other route.
	 *
	 * @param \Closure(): mixed $providerId the unified search provider, asked only for that route
	 */
	public static function group(mixed $route, \Closure $providerId): ?string {
		if (!is_string($route) || !isset(self::ROUTES[$route])) {
			return null;
		}
		if ($route === self::UNIFIED_SEARCH_ROUTE && !in_array($providerId(), self::PEOPLE_PROVIDERS, true)) {
			return null;
		}
		return self::ROUTES[$route];
	}

	/**
	 * The group of a WebDAV request, or null.
	 *
	 * - `REPORT` and `PROPFIND` on the system address book: addressbook.
	 * - `PROPFIND` with a depth other than 0 on `principals/users` or
	 *   `principals/groups` (the account list): addressbook.
	 * - `REPORT` on a principal collection (the principal search used to
	 *   find attendees and sharees): search.
	 *
	 * @param string $uri the request URI as the client sent it
	 * @param string $depth the Depth header; empty when the client sent none
	 */
	public static function davGroup(string $method, string $uri, string $depth): ?string {
		if ($method !== 'REPORT' && $method !== 'PROPFIND') {
			return null;
		}
		$root = strpos($uri, self::DAV_ROOT);
		if ($root === false) {
			return null;
		}
		$path = substr($uri, $root + strlen(self::DAV_ROOT));
		$query = strpos($path, '?');
		if ($query !== false) {
			$path = substr($path, 0, $query);
		}
		$segments = array_values(array_filter(explode('/', $path), static fn (string $s): bool => $s !== ''));
		$first = $segments[0] ?? '';
		if ($first === 'addressbooks') {
			return count($segments) >= 4 && rawurldecode($segments[3]) === self::SYSTEM_ADDRESS_BOOK ? self::GROUP_ADDRESSBOOK : null;
		}
		if ($first !== 'principals' || count($segments) > 2) {
			return null;
		}
		if ($method === 'REPORT') {
			return self::GROUP_SEARCH;
		}
		return count($segments) === 2 && in_array($segments[1], self::PRINCIPAL_COLLECTIONS, true) && $depth !== '0'
			? self::GROUP_ADDRESSBOOK
			: null;
	}
}
