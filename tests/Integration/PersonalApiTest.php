<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Http;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\Authentication\Token\IToken;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The personal API of the security section (concept section 15.1): every
 * endpoint only ever shows or changes the current user's own rows, and
 * "Log out everywhere else" ends only the other browser sessions.
 */
#[Group('DB')]
class PersonalApiTest extends PersonalApiTestCase {
	private IUser $alice;
	private IUser $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-pa-alice', 'alice@example.com');
		$this->bob = $this->user('ids-pa-bob', 'bob@example.com');
	}

	public function testEveryEndpointShowsOnlyTheUsersOwnRows(): void {
		$own = [];
		foreach ([$this->alice, $this->bob] as $i => $user) {
			$ip = '203.0.113.' . (10 + $i);
			$own[$user->getUID()] = [
				'detection' => $this->detection($user, $ip)->getId(),
				'network' => $this->trustedNetwork($user, $ip),
				'device' => $this->rememberDevice($user),
			];
			Server::get(LoginHistoryMapper::class)->insert($user->getUID(), time() - 60, SourceKey::fromIp($ip), 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
			for ($n = 0; $n <= $i; $n++) {
				Server::get(FailedLoginStats::class)->record($user->getUID(), SourceKey::fromIp($ip));
			}
		}
		$this->startSession($this->alice);
		$api = $this->controller();
		$alices = $own[$this->alice->getUID()];
		$bobs = $own[$this->bob->getUID()];

		$this->assertSame([$alices['detection']], array_column($api->detections()->getData(), 'id'));
		$this->assertSame([$alices['network']], array_column($api->trustedNetworks()->getData(), 'id'));
		$this->assertSame([$alices['device']], array_column($api->knownDevices()->getData(), 'id'));
		$logins = $api->logins()->getData();
		$this->assertSame(['203.0.113.10'], array_column($logins, 'ip'));
		$this->assertSame('Firefox on Linux', $logins[0]['device']);
		$overview = $api->overview()->getData();
		$this->assertSame(1, $overview['failedLogins']['total'], 'Bob\'s two failures are his');
		$this->assertSame(['203.0.113.10'], array_column($overview['failedLogins']['recent'], 'address'));

		$this->assertSame(Http::STATUS_NOT_FOUND, $api->deny($bobs['detection'])->getStatus());
		$this->assertSame(Http::STATUS_NOT_FOUND, $api->confirm($bobs['detection'])->getStatus());
		$this->assertSame(Http::STATUS_NOT_FOUND, $api->removeTrustedNetwork($bobs['network'])->getStatus());
		$this->assertSame(Http::STATUS_NOT_FOUND, $api->removeKnownDevice($bobs['device'])->getStatus());
		$this->assertNull(Server::get(DetectionMapper::class)->findById($bobs['detection'])->getUserVerdict());
		$this->assertCount(1, Server::get(TrustedNetworks::class)->forUser($this->bob->getUID()));
		$this->assertCount(1, $this->knownDevices()->forUser($this->bob->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en')));

		$json = json_encode([$api->detections()->getData(), $api->trustedNetworks()->getData(), $api->knownDevices()->getData(), $api->logins()->getData(), $api->overview()->getData()], JSON_THROW_ON_ERROR);
		$this->assertStringNotContainsString($this->bob->getUID(), $json);
		$this->assertStringNotContainsString('203.0.113.11', $json);
	}

	public function testWithTheSecurityPageOffOnlyTheAnswersAndTheChecklistAnswer(): void {
		$detection = $this->detection($this->alice, '203.0.113.10');
		$network = $this->trustedNetwork($this->alice, '203.0.113.10');
		$device = $this->rememberDevice($this->alice);
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::PERSONAL_PAGE_ENABLED, false);
		$this->startSession($this->alice);
		$api = $this->controller();

		$calls = [
			'detections' => static fn () => $api->detections(),
			'trustedNetworks' => static fn () => $api->trustedNetworks(),
			'removeTrustedNetwork' => static fn () => $api->removeTrustedNetwork($network),
			'knownDevices' => static fn () => $api->knownDevices(),
			'removeKnownDevice' => static fn () => $api->removeKnownDevice($device),
			'logins' => static fn () => $api->logins(),
			'securityChanges' => static fn () => $api->securityChanges(),
			'activity' => static fn () => $api->activity(),
			'overview' => static fn () => $api->overview(),
			'logOutElsewhere' => static fn () => $api->logOutElsewhere(),
			'secureAccountProgress' => static fn () => $api->secureAccountProgress(),
		];
		foreach ($calls as $name => $call) {
			try {
				$call();
				$this->fail($name . ' must not answer while the page is off');
			} catch (OCSNotFoundException) {
				$this->addToAssertionCount(1);
			}
		}
		$this->assertCount(1, Server::get(TrustedNetworks::class)->forUser($this->alice->getUID()), 'Nothing was removed');

		// The notification's "Was this you?" buttons and the checklist page still work.
		$this->assertSame(Http::STATUS_OK, $api->secureAccount()->getStatus());
		$this->assertSame(Http::STATUS_OK, $api->deny($detection->getId())->getStatus());
	}

	public function testTheOverviewSaysWhatNeedsTheUserNow(): void {
		$this->startSession($this->alice);
		$this->assertSame('ok', $this->controller()->overview()->getData()['status']['level']);

		$this->detection($this->alice, '203.0.113.10');
		$status = $this->controller()->overview()->getData()['status'];
		$this->assertSame('warning', $status['level']);
		$this->assertSame('One event needs your answer: was this you?', $status['headline']);
	}

	public function testLogOutEverywhereElseKeepsThisSessionAndAppPasswordsAndForgetsTheOtherDevices(): void {
		$laptop = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Firefox on the laptop');
		$phone = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Safari on the phone');
		$appPassword = $this->token($this->alice, IToken::PERMANENT_TOKEN, 'Desktop client');
		$bobs = $this->token($this->bob, IToken::TEMPORARY_TOKEN, 'Bob\'s browser');
		$otherDevice = $this->rememberDevice($this->alice);
		$thisDevice = $this->rememberDevice($this->alice);
		$bobsDevice = $this->rememberDevice($this->bob);
		$current = $this->startSession($this->alice);
		$this->cookies[$this->deviceCookieName()] = $this->deviceCookiesSet[1][0];
		$this->nextRequest();

		$response = $this->controller()->logOutElsewhere();

		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['sessions' => 2, 'devices' => 1], $response->getData());
		$this->assertTrue($this->tokenExists($current['id']), 'This session stays');
		$this->assertFalse($this->tokenExists($laptop['id']));
		$this->assertFalse($this->tokenExists($phone['id']));
		$this->assertTrue($this->tokenExists($appPassword['id']), 'App passwords are left to the device list');
		$this->assertTrue($this->tokenExists($bobs['id']), 'Never another account\'s');
		$this->assertSame([$thisDevice], array_column($this->controller()->knownDevices()->getData(), 'id'), 'This browser stays remembered');
		$this->assertNotContains($otherDevice, array_column($this->controller()->knownDevices()->getData(), 'id'));
		$this->assertSame([$bobsDevice], array_column($this->knownDevices()->forUser($this->bob->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en')), 'id'));
		$this->assertTrue($this->wasAudited('logged out everywhere else'));
		$this->assertNotNull($this->sessionUser, 'The user stays logged in');
	}

	public function testLogOutEverywhereElseNeedsABrowserSession(): void {
		$other = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Firefox on the laptop');
		$appPassword = $this->token($this->alice, IToken::PERMANENT_TOKEN, 'Desktop client');
		$this->session->id = $appPassword['secret'];
		$this->session->set('app_password', $appPassword['secret']);
		$this->sessionUser = $this->alice;

		$response = $this->controller()->logOutElsewhere();
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(PersonalApiController::NO_SESSION, $response->getData()['reason']);
		$this->assertTrue($this->tokenExists($other['id']));

		$this->session->clear();
		$this->session->id = $this->token($this->bob, IToken::TEMPORARY_TOKEN, 'Bob\'s browser')['secret'];
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->controller()->logOutElsewhere()->getStatus(), 'Only a session of the user itself');
		$this->assertTrue($this->tokenExists($other['id']));
		$this->assertFalse($this->wasAudited('logged out everywhere else'));
	}

}
