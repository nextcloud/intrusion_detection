<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\ConfirmationOverview;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Controller\ConfirmationApiController;
use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\LogOutElsewhere;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The endpoints of this step: the Confirmation tab (administrators only)
 * and the user's own remembered devices and logins.
 */
#[Group('DB')]
class ConfirmationApiTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-api', 'alice@example.com');
	}

	public function testTheConfirmationTabIsForAdministratorsOnly(): void {
		$class = new \ReflectionClass(ConfirmationApiController::class);
		$this->assertSame([], $class->getAttributes(NoAdminRequired::class));
		foreach (['index', 'accounts'] as $method) {
			$this->assertSame([], $class->getMethod($method)->getAttributes(NoAdminRequired::class), $method);
		}
	}

	public function testTheOverviewDescribesMethodsReasonsAccountsAndWaitingLogins(): void {
		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$bob = $this->user('ids-api-bob', null);
		$this->startSession($bob);
		$this->login($bob);
		$this->assertFalse($this->confirmationApi()->index()->getData()['approvals'][0]['canDecide'], 'Nobody decides on their own login');

		$this->sessionUser = Server::get(IUserManager::class)->get('admin');
		$data = $this->confirmationApi()->index(true)->getData();
		$this->assertSame(['second_factor', 'known_device', 'email_code', 'admin_approval'], array_column($data['methods'], 'id'));
		$this->assertSame('on', $data['methods'][3]['state']);
		$this->assertSame(['flagged_source', 'sprayed_password', 'protected_account', 'breached_password', 'risky_network', 'risk_high', 'lockdown'], array_column($data['policies'], 'id'));
		$this->assertSame([true, false, true, false, true, true, true], array_column($data['policies'], 'knownDeviceAllowed'));
		$this->assertSame('lockdown_known_device_ok', $data['policies'][6]['knownDeviceSetting'], 'Lockdown has its own switch, off by default');
		$this->assertFalse($data['policies'][6]['knownDevice']);
		$this->assertSame(['refuse', 'allow_notify', 'allow_force_change'], array_column($data['outcomes'], 'id'));
		$this->assertSame(['account', 'second_factor', 'devices', 'sharing', 'admin'], array_column($data['sensitive']['groups'], 'id'));
		$this->assertSame([true, true, true, true, true], array_column($data['sensitive']['groups'], 'enabled'), 'Every group is protected by default');
		$this->assertSame('sensitive_groups', $data['sensitive']['setting']);
		$this->assertCount(1, $data['approvals']);
		$this->assertSame($bob->getUID(), $data['approvals'][0]['uid']);
		$this->assertTrue($data['approvals'][0]['canDecide']);
		$this->assertGreaterThanOrEqual(1, $data['users']['active']);

		$this->assertSame(Http::STATUS_OK, $this->confirmationApi()->accounts(5000, -3)->getStatus(), 'The limit and offset are bounded');
	}

	public function testUsersListAndRemoveTheirOwnDevices(): void {
		$this->knownDevices()->remember($this->alice, SourceKey::fromIp($this->remoteAddress), 'Firefox/131.0 (X11; Linux)');
		$this->sessionUser = $this->alice;
		$list = $this->personalApi()->knownDevices()->getData();
		$this->assertCount(1, $list);
		$this->assertSame('Firefox on Linux', $list[0]['label']);

		$this->sessionUser = $this->user('ids-api-mallory', null);
		$this->assertSame([], $this->personalApi()->knownDevices()->getData(), 'Only one\'s own');
		$this->assertSame(Http::STATUS_NOT_FOUND, $this->personalApi()->removeKnownDevice($list[0]['id'])->getStatus());

		$this->sessionUser = $this->alice;
		$this->assertSame(Http::STATUS_OK, $this->personalApi()->removeKnownDevice($list[0]['id'])->getStatus());
		$this->assertSame([], $this->personalApi()->knownDevices()->getData());
		$this->assertCount(1, (new \ReflectionMethod(PersonalApiController::class, 'removeKnownDevice'))->getAttributes(UserRateLimit::class));
		$this->assertSame([], (new \ReflectionMethod(PersonalApiController::class, 'removeKnownDevice'))->getAttributes(NoCSRFRequired::class));
	}

	public function testUsersSeeTheirOwnRecentLogins(): void {
		$token = $this->startSession($this->alice);
		$mapper = Server::get(LoginHistoryMapper::class);
		$mapper->insert($this->alice->getUID(), time() - 60, SourceKey::fromIp('203.0.113.5'), 'Firefox', LoginHistory::METHOD_PASSWORD, true, 'known_device', 'confirmed', $token['id']);
		$mapper->insert($this->alice->getUID(), time() - 86400 * 40, SourceKey::fromIp('203.0.113.6'), null, LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
		$mapper->insert($this->user('ids-api-other', null)->getUID(), time() - 60, SourceKey::fromIp('203.0.113.7'), null, LoginHistory::METHOD_SSO, false, 'none', null, null);

		$this->sessionUser = $this->alice;
		$logins = $this->personalApi()->logins()->getData();
		$this->assertCount(1, $logins, 'The last 30 days, only one\'s own');
		$this->assertSame('203.0.113.5', $logins[0]['ip']);
		$this->assertTrue($logins[0]['current']);
		$this->assertSame('known_device', $logins[0]['confirmedBy']);
		$this->assertArrayNotHasKey('sessionTokenId', $logins[0]);
		$this->assertCount(2, $this->personalApi()->logins(365)->getData(), 'Further back, as long as the history is kept');
	}

	private function confirmationApi(): ConfirmationApiController {
		return new ConfirmationApiController(
			$this->request,
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->userSession,
			Server::get(ConfirmationOverview::class),
			Server::get(ConfirmationCoverage::class),
		);
	}

	private function personalApi(): PersonalApiController {
		return new PersonalApiController(
			$this->request,
			$this->userSession,
			Server::get(PersonalDetections::class),
			Server::get(WasThisYouService::class),
			Server::get(TrustedNetworks::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->knownDevices(),
			Server::get(LoginHistoryMapper::class),
			$this->currentSession,
			Server::get(SecureAccountGuide::class),
			Server::get(SecureAccountOverview::class),
			Server::get(SecurityChangeMapper::class),
			$this->settings,
			Server::get(ITimeFactory::class),
			Server::get(PersonalOverview::class),
			Server::get(LogOutElsewhere::class),
		);
	}
}
