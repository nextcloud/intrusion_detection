<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Settings\AuthorizedGroup;
use OC\Settings\AuthorizedGroupMapper;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClient;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Reasons\AdminOutsideNetworksReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * "Administrators log in from trusted networks only": a password login of
 * an administrator from outside the trusted networks needs confirmation.
 */
#[Group('DB')]
class AdminTrustedNetworksTest extends StepUpTestCase {
	private const OFFICE = '192.0.2.0/24';
	private const INSIDE = '192.0.2.40';
	private const OUTSIDE = '203.0.113.9';

	private IUser $admin;
	/** @var list<int> */
	private array $delegations = [];
	/** @var list<string> */
	private array $groups = [];

	protected function setUp(): void {
		parent::setUp();
		$this->admin = $this->user('ids-adminnet', 'admin@example.com');
		Server::get(IGroupManager::class)->get('admin')?->addUser($this->admin);
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY, true);
		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, [self::OFFICE]);
		$this->remoteAddress = self::OUTSIDE;
	}

	protected function tearDown(): void {
		$mapper = Server::get(AuthorizedGroupMapper::class);
		foreach ($this->delegations as $id) {
			$mapper->delete($mapper->find($id));
		}
		foreach ($this->groups as $gid) {
			Server::get(IGroupManager::class)->get($gid)?->delete();
		}
		parent::tearDown();
	}

	#[\Override]
	protected function stepUpReasons(): StepUpReasons {
		// A fresh reason per login, so that delegations made by the test are seen.
		return new StepUpReasons(new OverridingContainer([
			AdminOutsideNetworksReason::class => new AdminOutsideNetworksReason(
				$this->appSettings(),
				Server::get(IGroupManager::class),
				new DelegatedGroups(Server::get(AuthorizedGroupMapper::class), Server::get(LoggerInterface::class)),
			),
		]), Server::get(LoggerInterface::class));
	}

	public function testAnAdministratorOutsideTheTrustedNetworksMustConfirm(): void {
		$this->login($this->admin);

		$stepUp = $this->stepUp();
		$this->assertSame(ConfirmationStatus::Pending, $stepUp?->status);
		$this->assertSame([StepUpPolicy::AdminOutsideNetworks->value], $stepUp->policies);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $stepUp->methods);
		$this->assertSame('482915', $this->lastCode($this->admin->getUID()));
	}

	public function testTheConfirmationPageSaysWhy(): void {
		$this->login($this->admin);
		$response = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$params = $response->getParams();
		$this->assertStringStartsWith('You logged in from outside your trusted networks, so we need to confirm it\'s you.', $params['lead']);
		$this->assertSame('This login needs it because administrators may log in only from the trusted networks, and this address is outside them.', $params['why']);
		$this->assertStringEndsWith('unless your password itself is at risk or you log in from outside your trusted networks.', $params['rememberHint'], 'A remembered device is no way around the networks');
	}

	public function testInsideTheTrustedNetworksNothingIsAsked(): void {
		$this->remoteAddress = self::INSIDE;
		$this->login($this->admin);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->mailed);
	}

	public function testOtherAccountsAreNotAffected(): void {
		$bob = $this->user('ids-adminnet-user', 'bob@example.com');
		$this->login($bob);
		$this->assertNull($this->stepUp());
	}

	public function testDelegatedAdministratorsCount(): void {
		$gid = 'ids-adminnet-delegated-' . bin2hex(random_bytes(3));
		$group = Server::get(IGroupManager::class)->createGroup($gid);
		$this->assertNotNull($group);
		$this->groups[] = $gid;
		$carol = $this->user('ids-adminnet-delegated', 'carol@example.com');
		$group->addUser($carol);

		$this->login($carol);
		$this->assertNull($this->stepUp(), 'A plain group gives no administration rights');

		$delegation = new AuthorizedGroup();
		$delegation->setGroupId($gid);
		$delegation->setClass('OCA\\Settings\\Settings\\Admin\\Server');
		$this->delegations[] = Server::get(AuthorizedGroupMapper::class)->insert($delegation)->getId();
		$this->session->clear();
		$this->login($carol);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status);
	}

	public function testARememberedDeviceIsNotEnough(): void {
		$this->knownDevices()->remember($this->admin, SourceKey::fromIp(self::OUTSIDE), 'Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0');
		$this->nextRequest();
		$this->assertNotNull($this->knownDevices()->recognise($this->admin->getUID()), 'The device is known');

		$this->login($this->admin);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $this->stepUp()?->methods);
	}

	public function testAnAdministratorWithoutAWayToConfirmIsRefusedAndToldWhy(): void {
		$dave = $this->user('ids-adminnet-nothing', null);
		Server::get(IGroupManager::class)->get('admin')?->addUser($dave);
		$this->login($dave);

		$this->assertSame(ConfirmationStatus::Refused, $this->stepUp()?->status);
		$this->assertCount(1, $this->detectionsOf(StepUpRefused::ID));
		$response = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertSame(VerifyController::MODE_REFUSED, $response->getParams()['mode']);
		$this->assertSame('This login needs it because administrators may log in only from the trusted networks, and this address is outside them.', $response->getParams()['why']);
	}

	public function testAppsSendingThePasswordFromOutsideAreRefused(): void {
		$this->basicAuth($this->admin);
		$this->login($this->admin);
		$this->assertSame(ConfirmationStatus::RefusedClient, $this->stepUp()?->status);
		$this->assertNull($this->state->get(SessionMarkers::CONFIRMATION));
		$detections = $this->detectionsOf(StepUpRefusedClient::ID);
		$this->assertCount(1, $detections);
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$this->assertStringContainsString('administrators may log in only from the trusted networks', StepUpPolicy::describeAll($detections[0]->getExplanationData()['facts']['policies'], $l));
	}

	public function testAppsSendingThePasswordFromAFamiliarPlaceOutsideAreStillRefused(): void {
		Server::get(\OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks::class)->trust($this->admin->getUID(), SourceKey::fromIp(self::OUTSIDE));
		$this->basicAuth($this->admin);
		$this->login($this->admin);
		$this->assertSame(ConfirmationStatus::RefusedClient, $this->stepUp()?->status, 'A network of "Yes, it was me" is no trusted network');
	}

	public function testAppPasswordsFromOutsideAreNotAffected(): void {
		$this->headers['Authorization'] = 'Basic ' . base64_encode($this->admin->getUID() . ':app-password');
		$this->login($this->admin, 'xxxxx-xxxxx-xxxxx-xxxxx-xxxxx', tokenLogin: true);
		$this->assertNull($this->stepUp());
	}

	public function testWithTheSwitchOffNothingChanges(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY, false);
		$this->login($this->admin);
		$this->assertNull($this->stepUp());

		$this->session->clear();
		$this->basicAuth($this->admin);
		$this->login($this->admin);
		$this->assertNull($this->stepUp(), 'Apps sending the password too');
	}

	public function testWithoutTrustedNetworksEveryAdministratorLoginMustConfirm(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, []);
		$this->remoteAddress = self::INSIDE;
		$this->login($this->admin);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status);
	}
}
