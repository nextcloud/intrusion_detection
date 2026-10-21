<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Personal\ManageSummary;
use OCA\IntrusionDetection\Personal\PersonalActivity;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\Authentication\Token\IToken;
use OCP\IDBConnection;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The merged activity of the user's security page: open "Was this you?"
 * questions apart, everything else in one timeline, newest first, bounded,
 * and only ever the user's own rows.
 */
#[Group('DB')]
class PersonalActivityTest extends PersonalApiTestCase {
	private IUser $alice;
	private IUser $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-act-alice', 'alice@example.com');
		$this->bob = $this->user('ids-act-bob', 'bob@example.com');
		// Setting the test passwords recorded security changes of their own.
		Server::get(IDBConnection::class)->getQueryBuilder()->delete(SecurityChangeMapper::TABLE)->executeStatement();
	}

	public function testOpenQuestionsStandApartAndEverythingElseIsOneTimelineNewestFirst(): void {
		$now = time();
		$open = $this->detection($this->alice, '203.0.113.10');
		$answered = $this->detection($this->alice, '203.0.113.11');
		$this->setCreatedAt($open->getId(), $now - 86400 * 40);
		$this->setCreatedAt($answered->getId(), $now - 3600);
		Server::get(DetectionMapper::class)->setVerdict($answered->getId(), $this->alice->getUID(), 'confirmed', $now - 3000);
		$login = $this->loginAt($this->alice, $now - 7200, '198.51.100.7');
		$change = $this->change($this->alice, $now - 600);
		Server::get(FailedLoginStats::class)->record($this->alice->getUID(), SourceKey::fromIp('192.0.2.5'));
		Server::get(FailedLoginStats::class)->record($this->alice->getUID(), SourceKey::fromIp('192.0.2.5'));
		$this->startSession($this->alice);

		$activity = $this->controller()->activity()->getData();

		$this->assertSame([$open->getId()], array_column($activity['questions'], 'id'), 'An open question is listed however old it is');
		$this->assertTrue($activity['questions'][0]['asks']);
		$this->assertSame(['failed_logins', 'change', 'event', 'login'], array_column($activity['items'], 'kind'));
		$this->assertSame(['change-' . $change, 'event-' . $answered->getId(), 'login-' . $login], array_column(array_slice($activity['items'], 1), 'id'));
		[$failed, $changeItem, $event, $loginItem] = $activity['items'];
		$this->assertSame(['count' => 2], $failed['failedLogins']);
		$this->assertNull($failed['login']);
		$this->assertSame('password_changed', $changeItem['change']['type']);
		$this->assertSame('confirmed', $event['event']['verdict'], 'An answered question moves into the timeline with its answer');
		$this->assertSame('198.51.100.7', $loginItem['login']['ip']);
		$this->assertFalse($loginItem['login']['current']);
		$this->assertFalse($activity['hasMore']);
		$this->assertSame('UTC', $activity['timezone']);
		$this->assertSame(gmdate('Y-m-d', $now), $activity['today']);
		$this->assertSame(gmdate('Y-m-d', $now - 600), $changeItem['day']);
		$times = array_column($activity['items'], 'at');
		$sorted = $times;
		rsort($sorted);
		$this->assertSame($sorted, $times);
	}

	public function testALoginThatWaitedOutItsConfirmationIsNotShownAsWaiting(): void {
		$now = time();
		$waitedOut = $now - 900 - 60;
		$history = Server::get(LoginHistoryMapper::class);
		$old = $history->insert($this->alice->getUID(), $waitedOut, SourceKey::fromIp('198.51.100.7'), null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, null);
		$recent = $history->insert($this->alice->getUID(), $now - 60, SourceKey::fromIp('198.51.100.7'), null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, null);
		$this->startSession($this->alice);
		$api = $this->controller();

		$steps = array_column(array_column($api->activity()->getData()['items'], 'login'), 'stepUp', 'id');
		$this->assertSame(LoginHistory::STEP_UP_FAILED, $steps[$old]);
		$this->assertSame(LoginHistory::STEP_UP_PENDING, $steps[$recent], 'it may still be confirmed');
		$this->assertSame([$recent => 'pending', $old => 'failed'], array_column($api->logins()->getData(), 'stepUp', 'id'));

		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$this->assertSame([$recent => 'pending', $old => 'pending'], array_column($api->logins()->getData(), 'stepUp', 'id'), 'an administrator may still approve it');
	}

	public function testAnOldOpenQuestionIsListedBehindManyNewerDetections(): void {
		$now = time();
		$open = $this->detection($this->alice, '203.0.113.10');
		$this->setCreatedAt($open->getId(), $now - 86400 * 40);
		$mapper = Server::get(DetectionMapper::class);
		for ($i = 0; $i < PersonalDetections::MAX + 20; $i++) {
			$answered = $this->detection($this->alice, '203.0.113.' . (100 + $i % 100));
			$mapper->setVerdict($answered->getId(), $this->alice->getUID(), 'confirmed', $now - 60);
		}
		$this->startSession($this->alice);

		$activity = $this->controller()->activity(7, 10)->getData();
		$this->assertSame([$open->getId()], array_column($activity['questions'], 'id'));
		$this->assertCount(10, $activity['items']);
		$this->assertTrue($activity['hasMore']);
	}

	public function testDetectionsOfAnAskingCheckThatDoNotAskDoNotHideAnOpenQuestion(): void {
		$open = $this->detection($this->alice, '203.0.113.10');
		$this->setCreatedAt($open->getId(), time() - 86400 * 40);
		// Password spraying asks only for a login with the sprayed password, not for a flagged one.
		for ($i = 0; $i < PersonalActivity::MAX_QUESTIONS + 20; $i++) {
			$this->engine()->handle(new DetectionDraft(PasswordSpraying::ID, SourceKey::fromIp('198.51.100.' . (10 + $i)), $this->alice->getUID(), ['rule' => PasswordSpraying::RULE_FLAGGED]), []);
		}
		$this->startSession($this->alice);
		$this->assertSame([$open->getId()], array_column($this->controller()->activity()->getData()['questions'], 'id'));
	}

	public function testOpenQuestionsAreBounded(): void {
		for ($i = 0; $i < PersonalActivity::MAX_QUESTIONS + 3; $i++) {
			$this->detection($this->alice, '203.0.113.' . (10 + $i));
		}
		$this->startSession($this->alice);
		$this->assertCount(PersonalActivity::MAX_QUESTIONS, $this->controller()->activity()->getData()['questions']);
	}

	public function testTheTimelineIsBoundedAndSaysWhenThereIsMore(): void {
		$now = time();
		for ($i = 1; $i <= PersonalActivity::MAX_LIMIT + 5; $i++) {
			$this->loginAt($this->alice, $now - $i * 60, '198.51.100.7');
		}
		$this->loginAt($this->alice, $now - 86400 * 2, '198.51.100.8');
		$this->startSession($this->alice);
		$api = $this->controller();

		$three = $api->activity(30, 3)->getData();
		$this->assertCount(3, $three['items']);
		$this->assertTrue($three['hasMore']);
		$this->assertSame($now - 60, $three['items'][0]['at']);

		$this->assertCount(1, $api->activity(30, 0)->getData()['items'], 'At least one');
		$all = $api->activity(30, 100000)->getData();
		$this->assertCount(PersonalActivity::MAX_LIMIT, $all['items'], 'At most MAX_LIMIT');
		$this->assertTrue($all['hasMore']);

		$day = $api->activity(1, 100)->getData();
		$this->assertCount(PersonalActivity::MAX_LIMIT, $day['items']);
		$this->assertNotContains('198.51.100.8', array_column(array_column($day['items'], 'login'), 'ip'), 'Older than the window');
		$this->assertCount(1, $api->activity(-5, 1)->getData()['items'], 'At least one day');
	}

	public function testEveryEntryIsTheUsersOwn(): void {
		foreach ([$this->alice, $this->bob] as $i => $user) {
			$ip = '203.0.113.' . (20 + $i);
			$this->detection($user, $ip);
			$answered = $this->detection($user, $ip);
			Server::get(DetectionMapper::class)->setVerdict($answered->getId(), $user->getUID(), 'denied', time());
			$this->loginAt($user, time() - 60, $ip);
			$this->change($user, time() - 30, $ip);
			Server::get(FailedLoginStats::class)->record($user->getUID(), SourceKey::fromIp($ip));
		}
		$this->startSession($this->alice);

		$activity = $this->controller()->activity()->getData();

		$this->assertCount(1, $activity['questions']);
		$this->assertEqualsCanonicalizing(['change', 'login', 'failed_logins', 'event'], array_column($activity['items'], 'kind'));
		$json = json_encode($activity, JSON_THROW_ON_ERROR);
		$this->assertStringNotContainsString($this->bob->getUID(), $json);
		$this->assertStringNotContainsString('203.0.113.21', $json);
		$this->assertStringContainsString('203.0.113.20', $json);
	}

	public function testTheActivityIsNotFoundWhileTheSecurityPageIsOff(): void {
		$this->loginAt($this->alice, time() - 60, '198.51.100.7');
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::PERSONAL_PAGE_ENABLED, false);
		$this->startSession($this->alice);

		$this->expectException(OCSNotFoundException::class);
		$this->controller()->activity();
	}

	public function testManageCountsTheUsersOwnDevicesNetworksAndOtherBrowsers(): void {
		$this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Firefox on the laptop');
		$this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Safari on the phone');
		$this->token($this->alice, IToken::PERMANENT_TOKEN, 'Desktop client');
		$this->token($this->bob, IToken::TEMPORARY_TOKEN, 'Bob\'s browser');
		$this->rememberDevice($this->alice);
		$this->rememberDevice($this->bob);
		$this->trustedNetwork($this->bob, '203.0.113.30');
		$this->startSession($this->alice);

		$summary = $this->manage()->forUser($this->alice->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));

		$this->assertSame(['devices' => 1, 'networks' => 0, 'otherBrowsers' => 2], $summary, 'Not this session, not the app password, nothing of Bob\'s');
	}

	public function testManageOffersNothingToABrandNewAccount(): void {
		$this->startSession($this->alice);

		$summary = $this->manage()->forUser($this->alice->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));

		$this->assertSame(['devices' => 0, 'networks' => 0, 'otherBrowsers' => 0], $summary);
	}

	private function manage(): ManageSummary {
		return new ManageSummary($this->knownDevices(), Server::get(TrustedNetworks::class), Server::get(Tokens::class), $this->currentSession);
	}

	private function loginAt(IUser $user, int $at, string $ip): int {
		return Server::get(LoginHistoryMapper::class)->insert($user->getUID(), $at, SourceKey::fromIp($ip), 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
	}

	private function change(IUser $user, int $at, ?string $ip = null): int {
		return Server::get(SecurityChangeMapper::class)->insert([
			'uid' => $user->getUID(),
			'type' => 'password_changed',
			'via' => 'self',
			'actor_uid' => null,
			'old_value_hint' => null,
			'new_value_hint' => null,
			'notify_to' => null,
			'ref_id' => null,
			'detail' => null,
			'session_token_id' => null,
			'ip' => $ip,
			'created_at' => $at,
		]);
	}

	private function setCreatedAt(int $id, int $at): void {
		$qb = Server::get(IDBConnection::class)->getQueryBuilder();
		$qb->update(DetectionMapper::TABLE)
			->set('created_at', $qb->createNamedParameter($at))
			->set('last_seen_at', $qb->createNamedParameter($at))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)))
			->executeStatement();
	}
}
