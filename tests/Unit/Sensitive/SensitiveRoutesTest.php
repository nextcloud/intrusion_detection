<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Sensitive;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Sensitive\SensitiveRoutes;
use OCP\L10N\IFactory;
use OCP\Route\IRouter;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class SensitiveRoutesTest extends TestCase {
	/**
	 * Every listed route exists, so the list cannot drift from core's routes
	 * silently (concept section 4, verify item 13). Boots the router with
	 * the routes of every enabled app.
	 */
	public function testEveryListedRouteExists(): void {
		$router = Server::get(IRouter::class);
		$router->loadRoutes();
		$names = array_keys($router->getRouteCollection()->all());
		foreach (array_keys(SensitiveRoutes::ROUTES) as $route) {
			$this->assertContains($route, $names, 'The route ' . $route . ' no longer exists');
		}
	}

	/**
	 * Real URLs of the actions, as core's router matches them, reach the table.
	 *
	 * @return array<string, array{string, string, string}>
	 */
	public static function urls(): array {
		return [
			'app password in the settings' => ['POST', '/settings/personal/authtokens', SensitiveRoutes::GROUP_DEVICES],
			'own password' => ['POST', '/settings/personal/changepassword', SensitiveRoutes::GROUP_ACCOUNT],
			'login flow v2 grant' => ['POST', '/login/v2/grant', SensitiveRoutes::GROUP_DEVICES],
			'backup codes' => ['POST', '/apps/twofactor_backupcodes/settings/create', SensitiveRoutes::GROUP_SECOND_FACTOR],
			'two-factor enforcement' => ['PUT', '/settings/api/admin/twofactorauth', SensitiveRoutes::GROUP_ADMIN],
			'this app\'s settings' => ['PUT', '/ocsapp/apps/intrusion_detection/api/v1/settings', SensitiveRoutes::GROUP_ADMIN],
		];
	}

	#[DataProvider('urls')]
	public function testCoresRouterMatchesTheActionsToTheirRoute(string $method, string $url, string $group): void {
		$router = Server::get(IRouter::class);
		$context = $router->getGenerator()->getContext();
		$previous = $context->getMethod();
		$context->setMethod($method);
		try {
			$route = $router->findMatchingRoute($url)['_route'] ?? null;
		} finally {
			$context->setMethod($previous);
		}
		$this->assertIsString($route);
		$this->assertSame($group, SensitiveRoutes::group($route, static fn (): mixed => null, false));
	}

	public function testTheLockdownEndpointsAreNeverSensitive(): void {
		$router = Server::get(IRouter::class);
		$router->loadRoutes();
		$names = array_keys($router->getRouteCollection()->all());
		foreach (['index', 'start', 'extend', 'end'] as $action) {
			$this->assertContains('ocs.intrusion_detection.lockdownapi.' . $action, $names);
		}
		foreach (array_keys(SensitiveRoutes::ROUTES) as $route) {
			$this->assertStringNotContainsString('lockdown', $route, 'Ending a lockdown must never need a confirmation the lockdown asks for');
		}
	}

	public function testEveryGroupIsASettingWithTextsForThePage(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->assertSame(SensitiveRoutes::GROUPS, (new GlobalSettings())->get(GlobalSettings::SENSITIVE_GROUPS)?->default, 'Every group is on by default');
		foreach (SensitiveRoutes::GROUPS as $group) {
			$this->assertMatchesRegularExpression(SensitiveRoutes::GROUP_PATTERN, $group);
			$this->assertNotSame($group, SensitiveRoutes::groupLabel($group, $l));
			$this->assertNotSame([], SensitiveRoutes::groupExamples($group, $l));
		}
		foreach (SensitiveRoutes::ROUTES as [$group]) {
			$this->assertContains($group, SensitiveRoutes::GROUPS);
		}
	}

	/**
	 * @return array<string, array{string, array<string, mixed>, bool, ?string}>
	 */
	public static function requests(): array {
		return [
			'email by the account edit' => ['ocs.provisioning_api.users.edituser', ['key' => 'email'], false, SensitiveRoutes::GROUP_ACCOUNT],
			'password by the account edit' => ['ocs.provisioning_api.users.edituser', ['key' => 'password'], false, SensitiveRoutes::GROUP_ACCOUNT],
			'phone number' => ['ocs.provisioning_api.users.edituser', ['key' => 'phone'], false, null],
			'display name, not included' => ['ocs.provisioning_api.users.edituser', ['key' => 'displayname'], false, null],
			'display name, included' => ['ocs.provisioning_api.users.edituser', ['key' => 'displayname'], true, SensitiveRoutes::GROUP_ACCOUNT],
			'display name in user management, included' => ['settings.users.setdisplayname', [], true, SensitiveRoutes::GROUP_ACCOUNT],
			'display name in user management, not included' => ['settings.users.setdisplayname', [], false, null],
			'several fields with an email' => ['ocs.provisioning_api.users.editusermultifield', ['email' => 'new@example.com'], false, SensitiveRoutes::GROUP_ACCOUNT],
			'several fields with the admin group' => ['ocs.provisioning_api.users.editusermultifield', ['email' => 'x@example.com', 'groups' => ['staff', 'admin']], false, SensitiveRoutes::GROUP_ADMIN],
			'several fields, only the quota' => ['ocs.provisioning_api.users.editusermultifield', ['quota' => '5 GB'], false, null],
			'an additional email address' => ['ocs.provisioning_api.users.editusermultivalue', ['collectionName' => 'additional_mail'], false, SensitiveRoutes::GROUP_ACCOUNT],
			'joining the admin group' => ['ocs.provisioning_api.users.addtogroup', ['groupid' => 'admin'], false, SensitiveRoutes::GROUP_ADMIN],
			'joining another group' => ['ocs.provisioning_api.users.addtogroup', ['groupid' => 'staff'], false, null],
			'a new account' => ['ocs.provisioning_api.users.adduser', [], false, SensitiveRoutes::GROUP_ADMIN],
			'an app password' => ['settings.authsettings.create', [], false, SensitiveRoutes::GROUP_DEVICES],
			'a share' => ['ocs.files_sharing.shareapi.createshare', ['shareType' => 3, 'path' => '/'], false, SensitiveRoutes::GROUP_SHARING],
			'files' => ['files.view.index', [], false, null],
			'no route' => ['', [], false, null],
		];
	}

	/**
	 * @param array<string, mixed> $params
	 */
	#[DataProvider('requests')]
	public function testTheParametersDecideWhereTheyMatter(string $route, array $params, bool $includeDisplayName, ?string $group): void {
		$asked = [];
		$param = static function (string $name) use ($params, &$asked): mixed {
			$asked[] = $name;
			return $params[$name] ?? null;
		};
		$this->assertSame($group, SensitiveRoutes::group($route, $param, $includeDisplayName));
		if (!isset(SensitiveRoutes::ROUTES[$route]) || SensitiveRoutes::ROUTES[$route][1] === SensitiveRoutes::RULE_ALWAYS) {
			$this->assertSame([], $asked, 'Parameters are only read for the routes they decide');
		}
	}

	/**
	 * @return array<string, array{mixed, bool}>
	 */
	public static function shareTypes(): array {
		return [
			'public link' => [3, true],
			'federated' => ['6', true],
			'federated group' => [9, true],
			'a user on this server' => [0, false],
			'a group on this server' => [1, false],
			'nothing' => [null, false],
		];
	}

	#[DataProvider('shareTypes')]
	public function testOnlySharesThatReachOutsideCount(mixed $type, bool $outside): void {
		$this->assertSame($outside, SensitiveRoutes::isOutsideShare(static fn (string $name): mixed => $name === 'shareType' ? $type : null));
		$this->assertTrue(SensitiveRoutes::needsShareCheck('ocs.files_sharing.shareapi.createshare'));
		$this->assertFalse(SensitiveRoutes::needsShareCheck('settings.authsettings.create'));
	}
}
