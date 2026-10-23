<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Sensitive;

use OCA\IntrusionDetection\Check\Checks\DirectoryScraping\DirectoryScraping;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCP\Route\IRouter;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class DirectoryRoutesTest extends TestCase {
	/**
	 * Every listed route exists, so the list cannot drift from the routes
	 * silently (concept section 4, verify item 13). Boots the router with the
	 * routes of every enabled app.
	 */
	public function testEveryListedRouteExists(): void {
		$router = Server::get(IRouter::class);
		$router->loadRoutes();
		$names = array_keys($router->getRouteCollection()->all());
		foreach (array_keys(DirectoryRoutes::ROUTES) as $route) {
			$this->assertContains($route, $names, 'The route ' . $route . ' no longer exists');
		}
	}

	public function testEveryGroupHasALimit(): void {
		$this->assertSame(DirectoryRoutes::GROUPS, array_keys(DirectoryScraping::LIMITS));
		foreach (DirectoryRoutes::ROUTES as $group) {
			$this->assertContains($group, DirectoryRoutes::GROUPS);
		}
	}

	/**
	 * @return array<string, array{?string, ?string, ?string}>
	 */
	public static function routes(): array {
		return [
			'autocomplete' => ['ocs.core.autocomplete.get', null, DirectoryRoutes::GROUP_SEARCH],
			'sharees' => ['ocs.files_sharing.shareesapi.search', null, DirectoryRoutes::GROUP_SEARCH],
			'contacts menu' => ['core.contactsmenu.index', null, DirectoryRoutes::GROUP_SEARCH],
			'unified search for users' => ['ocs.core.unifiedsearch.search', 'users', DirectoryRoutes::GROUP_SEARCH],
			'unified search for contacts' => ['ocs.core.unifiedsearch.search', 'contacts', DirectoryRoutes::GROUP_SEARCH],
			'unified search for files' => ['ocs.core.unifiedsearch.search', 'files', null],
			'profile page' => ['profile.profilepage.index', null, DirectoryRoutes::GROUP_PROFILE],
			'avatar' => ['core.avatar.getavatar', null, DirectoryRoutes::GROUP_PROFILE],
			'user list' => ['ocs.provisioning_api.users.getusersdetails', null, DirectoryRoutes::GROUP_USERS],
			'files' => ['files.view.index', null, null],
			'own avatar upload' => ['core.avatar.postavatar', null, null],
			'no route' => [null, null, null],
		];
	}

	#[DataProvider('routes')]
	public function testAppRoutes(?string $route, ?string $provider, ?string $group): void {
		$asked = false;
		$this->assertSame($group, DirectoryRoutes::group($route, function () use ($provider, &$asked): ?string {
			$asked = true;
			return $provider;
		}));
		$this->assertSame($route === DirectoryRoutes::UNIFIED_SEARCH_ROUTE, $asked, 'The provider is only read for unified search');
	}

	/**
	 * @return array<string, array{string, string, string, ?string}>
	 */
	public static function davRequests(): array {
		$book = '/remote.php/dav/addressbooks/users/alice/z-server-generated--system/';
		return [
			'system address book sync' => ['REPORT', $book, '1', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'system address book listing' => ['PROPFIND', $book, '1', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'a card of it' => ['PROPFIND', $book . 'Database:bob.vcf', '0', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'with a web root and query' => ['REPORT', '/nextcloud' . $book . '?x=1', '1', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'own address book' => ['REPORT', '/remote.php/dav/addressbooks/users/alice/contacts/', '1', null],
			'downloading a card' => ['GET', $book . 'Database:bob.vcf', '', null],
			'principal search' => ['REPORT', '/remote.php/dav/principals/', '0', DirectoryRoutes::GROUP_SEARCH],
			'principal search on users' => ['REPORT', '/remote.php/dav/principals/users/', '0', DirectoryRoutes::GROUP_SEARCH],
			'listing every account' => ['PROPFIND', '/remote.php/dav/principals/users/', '1', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'listing without depth' => ['PROPFIND', '/remote.php/dav/principals/groups', '', DirectoryRoutes::GROUP_ADDRESSBOOK],
			'the collection itself' => ['PROPFIND', '/remote.php/dav/principals/users/', '0', null],
			'own principal' => ['PROPFIND', '/remote.php/dav/principals/users/alice/', '0', null],
			'own principal report' => ['REPORT', '/remote.php/dav/principals/users/alice/', '0', null],
			'files' => ['PROPFIND', '/remote.php/dav/files/alice/', '1', null],
			'legacy files' => ['PROPFIND', '/remote.php/webdav/', '1', null],
		];
	}

	#[DataProvider('davRequests')]
	public function testDavRequests(string $method, string $uri, string $depth, ?string $group): void {
		$this->assertSame($group, DirectoryRoutes::davGroup($method, $uri, $depth));
	}
}
