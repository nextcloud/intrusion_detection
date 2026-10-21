<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\KnownDevice\DeviceCookie;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\KnownDeviceListener;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\User\Events\PasswordUpdatedEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Known devices (concept section 11.5.1): remembered only after a
 * confirmed login and only when the user chose it, recognised silently
 * where the reason allows it, stored only as a fingerprint, and forgotten
 * when they may no longer prove anything.
 */
#[Group('DB')]
class KnownDevicesTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-device', 'alice@example.com');
		$this->headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testADeviceIsRememberedOnlyAfterAConfirmedLoginAndOnlyWhenChosen(): void {
		$this->freshLogin();
		$page = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		$this->assertTrue($page->getParams()['canRemember']);
		$this->assertStringContainsString('Remember this device', $page->render());
		$this->assertSame([], $this->deviceCookiesSet, 'Nothing before the login is confirmed');

		$this->verifyController()->confirm('482915', '', '');
		$this->assertSame([], $this->deviceCookiesSet, 'Not chosen: not remembered');
		$this->assertSame(0, $this->deviceRows());

		$this->freshLogin();
		$this->verifyController()->confirm('000000', '', '1');
		$this->assertSame([], $this->deviceCookiesSet, 'A wrong code remembers nothing');
		$this->verifyController()->confirm((string)$this->lastCode($this->alice->getUID()), '', '1');
		$this->assertCount(1, $this->deviceCookiesSet);
		[$deviceId, $expires] = $this->deviceCookiesSet[0];
		$this->assertTrue(DeviceCookie::isValid($deviceId));
		$this->assertEqualsWithDelta(time() + KnownDevices::MAX_DURATION, $expires, 5);
		$this->assertSame(1, $this->deviceRows());

		$row = $this->rows()[0];
		$this->assertSame(64, strlen($row['device_hmac']));
		$this->assertStringNotContainsString($deviceId, json_encode($row, JSON_THROW_ON_ERROR), 'Only a keyed fingerprint is stored');
		$this->assertSame('firefox', $row['family']);
		$this->assertSame('linux', $row['platform']);
		$this->assertSame('Firefox on Linux', $row['label']);
		$this->assertSame(SourceKey::fromIp($this->remoteAddress)->netKey, $row['net_key']);
	}

	public function testARememberedDeviceConfirmsTheNextLoginSilently(): void {
		$this->rememberDevice();
		$this->mailed = [];
		$this->freshLogin(StepUpState::PENDING, expectPending: false);
		$this->assertNull($this->stepUp(), 'Nothing is asked');
		$this->assertSame('known_device', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null);
		$this->assertSame([], $this->mailed, 'No code is sent');
	}

	public function testADeviceNeverConfirmsALoginWithASprayedPassword(): void {
		$this->rememberDevice();
		foreach (Server::get(Fingerprinter::class)->passwordFlagFingerprints(self::PASSWORD) as $fingerprint) {
			Server::get(FlaggedSources::class)->flagPassword(bin2hex($fingerprint));
		}
		$this->freshLogin();
		$this->assertSame(['flagged_source', 'sprayed_password'], $this->stepUp()?->policies);
		$this->assertSame(['email_code'], $this->stepUp()?->methods, 'The device does not count; the email code does');
	}

	public function testTheSettingsDecideWhetherADeviceCounts(): void {
		$this->rememberDevice();
		$this->settings->setGlobal(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR, ['protected_account']);
		$this->freshLogin();
		$this->assertSame(['email_code'], $this->stepUp()?->methods);

		$this->settings->setGlobal(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR, ['flagged_source']);
		$this->settings->setGlobal(GlobalSettings::KNOWN_DEVICE_ENABLED, false);
		$this->freshLogin();
		$this->assertSame(['email_code'], $this->stepUp()?->methods, 'Switched off: no device is recognised');
		$page = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		$this->assertFalse($page->getParams()['canRemember']);
	}

	public function testADeviceExpiresAfterItsDurationWithoutUse(): void {
		$this->rememberDevice();
		$this->settings->setGlobal(GlobalSettings::KNOWN_DEVICE_DURATION, 86400 * 2);
		$this->ageDevices(86400 * 3);
		$this->freshLogin();
		$this->assertSame(['email_code'], $this->stepUp()?->methods, 'Too long unused');

		$this->invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertSame(0, $this->deviceRows(), 'Removed by the cleanup job');
	}

	public function testUseIsNotedAtMostOnceADayAndRenewsTheCookie(): void {
		$this->rememberDevice();
		$this->ageDevices(3600);
		$this->deviceCookiesSet = [];
		$this->freshLogin(expectPending: false);
		$this->assertSame([], $this->deviceCookiesSet, 'Used within the day: nothing written');
		$before = (int)$this->rows()[0]['last_seen_at'];

		$this->ageDevices(86400 * 2);
		$this->freshLogin(expectPending: false);
		$this->assertCount(1, $this->deviceCookiesSet, 'The cookie is renewed');
		$this->assertGreaterThan($before, (int)$this->rows()[0]['last_seen_at']);
	}

	public function testAnAccountKeepsAtMostFiftyDevices(): void {
		$devices = $this->knownDevices();
		for ($i = 0; $i < KnownDevices::MAX_PER_USER + 3; $i++) {
			$this->assertTrue($devices->remember($this->alice, SourceKey::fromIp($this->remoteAddress), 'Firefox/131.0'));
		}
		$this->assertSame(KnownDevices::MAX_PER_USER, $this->deviceRows());
	}

	public function testNoItWasNotMeForgetsEveryDevice(): void {
		$this->rememberDevice();
		$this->knownDevices()->remember($this->alice, null, null);
		$detection = new Detection();
		$detection->setUid($this->alice->getUID());
		$this->deviceListener()->handle(new WasThisYouAnsweredEvent($detection, Detection::VERDICT_DENIED));
		$this->assertSame(0, $this->deviceRows());

		$this->rememberDevice();
		$this->deviceListener()->handle(new WasThisYouAnsweredEvent($detection, Detection::VERDICT_CONFIRMED));
		$this->assertSame(1, $this->deviceRows(), '"Yes" forgets nothing');
	}

	public function testANewPasswordForgetsTheOtherDevices(): void {
		$this->rememberDevice();
		$current = $this->cookies[$this->deviceCookieName()];
		$this->knownDevices()->remember($this->alice, null, null);
		$this->cookies[$this->deviceCookieName()] = $current;
		$this->assertSame(2, $this->deviceRows());

		$this->sessionUser = $this->alice;
		$this->deviceListener()->handle(new PasswordUpdatedEvent($this->alice, 'New-Password-2026!'));
		$this->assertSame(1, $this->deviceRows(), 'The browser the user changed it from stays');
		$this->assertNotNull($this->knownDevices()->recognise($this->alice->getUID()));

		$this->sessionUser = null;
		$this->deviceListener()->handle(new PasswordUpdatedEvent($this->alice, 'Admin-Set-Password-2026!'));
		$this->assertSame(0, $this->deviceRows(), 'Set by someone else: all are forgotten');
	}

	public function testACredentialUsedFromTwoNetworksForgetsTheCurrentDevice(): void {
		$this->rememberDevice();
		$this->deviceCookiesSet = [];
		$this->knownDevices()->forgetCurrentDevice($this->alice->getUID(), 99);
		$this->assertSame(0, $this->deviceRows());
		$this->assertSame(1, $this->deviceCookiesSet[0][1] ?? null, 'The cookie is cleared');
		$this->knownDevices()->forgetCurrentDevice($this->alice->getUID(), 99);
		$this->assertCount(1, $this->deviceCookiesSet, 'Nothing left to forget');
	}

	public function testUsersSeeAndRemoveOnlyTheirOwnDevices(): void {
		$this->rememberDevice();
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$list = $this->knownDevices()->forUser($this->alice->getUID(), $l);
		$this->assertCount(1, $list);
		$this->assertSame('Firefox on Linux', $list[0]['label']);
		$this->assertTrue($list[0]['current']);
		$this->assertArrayNotHasKey('device_hmac', $list[0]);

		$bob = $this->user('ids-device-bob', 'bob@example.com');
		$this->assertFalse($this->knownDevices()->remove($bob->getUID(), $list[0]['id']), 'Not Bob\'s');
		$this->assertSame(1, $this->deviceRows());
		$this->deviceCookiesSet = [];
		$this->assertTrue($this->knownDevices()->remove($this->alice->getUID(), $list[0]['id']));
		$this->assertSame(0, $this->deviceRows());
		$this->assertSame(1, $this->deviceCookiesSet[0][1] ?? null, 'Removing the current device clears its cookie');
	}

	public function testADeletedAccountLeavesNoDevice(): void {
		$this->rememberDevice();
		Server::get(UserDataCleanup::class)->deleteUser($this->alice->getUID());
		$this->assertSame(0, $this->deviceRows());
	}

	/**
	 * A login with the password from the flagged address, in a new session.
	 */
	private function freshLogin(string $status = StepUpState::PENDING, bool $expectPending = true): void {
		$this->session->clear();
		$this->nextRequest();
		$this->startSession($this->alice);
		$this->login($this->alice);
		if ($expectPending) {
			$this->assertSame($status, $this->stepUp()?->status);
		}
	}

	private function rememberDevice(): void {
		$this->freshLogin();
		$this->verifyController()->confirm((string)$this->lastCode($this->alice->getUID()), '', '1');
		$this->assertArrayHasKey($this->deviceCookieName(), $this->cookies);
	}

	private function deviceListener(): KnownDeviceListener {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturnCallback(fn (): ?IUser => $this->sessionUser);
		return new KnownDeviceListener($this->knownDevices(), $session, Server::get(LoggerInterface::class));
	}

	private function ageDevices(int $seconds): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(KnownDeviceMapper::TABLE)
			->set('last_seen_at', $qb->createNamedParameter(Server::get(ITimeFactory::class)->getTime() - $seconds))
			->executeStatement();
	}

	private function deviceRows(): int {
		return count($this->rows());
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function rows(): array {
		$result = $this->db->getQueryBuilder()->select('*')->from(KnownDeviceMapper::TABLE)->orderBy('id')->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		return $rows;
	}
}
