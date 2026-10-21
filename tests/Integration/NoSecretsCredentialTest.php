<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\Authentication\Token\IToken;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 18 for the credential check: app passwords, passwords,
 * session cookies and the credential keys derived from them appear in no
 * table, detection, notification, email, narrative or log line. The keys
 * exist in the memory cache only.
 */
#[Group('DB')]
class NoSecretsCredentialTest extends CredentialUseTestCase {
	public function testNoCredentialOrCredentialKeyLeavesTheMemoryCache(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		$this->settings->setResponses(TokenConcurrentUse::ID, [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser]);
		$user = $this->newUser('ids-secret', 'secret@example.com');
		$password = 'A-long-test-password-' . $user->getUID();
		$appPassword = $this->token($user, IToken::PERMANENT_TOKEN, 'Desktop client');
		$session = $this->token($user, IToken::TEMPORARY_TOKEN, 'Firefox on Linux');
		$madeUp = 'Made-Up-Basic-Password-9f9f';
		$secrets = [
			'app password' => $appPassword['secret'],
			'session cookie' => $session['secret'],
			'login password' => $password,
			'made-up password' => $madeUp,
		];

		$scenarios = [
			[$this->basic($user->getUID(), $appPassword['secret']), [], $this->appPasswordLogin($user, $appPassword)],
			[$this->basic($user->getUID(), $password), [], $this->passwordLogin($user)],
			[[], [$this->cookieName => $session['secret']], $this->loggedInSession($user, $session)],
		];
		foreach ($scenarios as [$server, $cookies, $login]) {
			foreach ([self::HOME, self::AWAY, self::HOME, self::AWAY] as $ip) {
				$this->send($ip, $server, $cookies, $login);
			}
			$this->now += 3600;
		}
		$browser = $this->token($user, IToken::TEMPORARY_TOKEN, 'Chrome on Windows');
		$secrets['second session cookie'] = $browser['secret'];
		$cookie = [$this->cookieName => $browser['secret']];
		foreach ([self::HOME, self::AWAY, self::HOME, self::AWAY] as $i => $ip) {
			$this->send($ip, $i % 2 === 1 ? $this->basic($user->getUID(), $madeUp) : [], $cookie, $this->loggedInSession($user, $browser));
		}

		$detections = Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [TokenConcurrentUse::ID]));
		$this->assertCount(4, $detections, 'The scenarios ran: app password, password, session, session behind a made-up header');
		$this->assertCount(4, $this->cachedKeys(), 'One key per credential that logged in: app password, password, two sessions');
		foreach ($this->cachedKeys() as $key) {
			$this->assertStringStartsWith(CredentialTracker::KEY_PREFIX, $key);
			$secrets['credential key ' . $key] = substr($key, strlen(CredentialTracker::KEY_PREFIX));
		}

		foreach (IntegrationTestCase::TABLES as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, $table);
			$result->closeCursor();
		}
		$this->assertNotSame([], CapturingNotificationApp::$notifications);
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secrets, 'notification');
		}
		$this->assertNotSame([], $this->mailed);
		foreach ($this->mailed as [, $mail]) {
			$this->assertClean(json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR), $secrets, 'email');
		}
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach ($detections as $detection) {
			$this->assertClean(json_encode($detection->jsonSerialize()), $secrets, 'detection');
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray()), $secrets, 'narrative');
		}
		$this->assertClean(implode("\n", $this->logged), $secrets, 'app log');
		$this->assertClean(is_file($logFile) ? (string)file_get_contents($logFile, false, null, $logOffset) : '', $secrets, 'server log');
	}

	/**
	 * @param array<string, string> $secrets
	 */
	private function assertClean(string $text, array $secrets, string $where): void {
		foreach ($secrets as $name => $secret) {
			$this->assertStringNotContainsString($secret, $text, 'The ' . $name . ' is in the ' . $where);
		}
	}

	/**
	 * @return list<string>
	 */
	private function cachedKeys(): array {
		return array_map('strval', array_keys((new \ReflectionProperty($this->cache, 'cachedData'))->getValue($this->cache)));
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}
}
