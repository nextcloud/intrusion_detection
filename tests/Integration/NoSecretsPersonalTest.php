<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\DecoyCredentialDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\ReservedNameDetector;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\Authentication\Token\IToken;
use OCP\IConfig;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Concept section 18 for the user's security section: no password, password
 * fingerprint, session id, app password or device cookie reaches the
 * failed-login counts, any personal API response or the log.
 */
#[Group('DB')]
class NoSecretsPersonalTest extends PersonalApiTestCase {
	public function testNoSecretReachesThePersonalApiOrTheFailedLoginCounts(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		$alice = $this->user('ids-secret-personal', 'alice@example.com');
		$wrong = 'Secret-Wrong-Password-For-The-Page-3c3c';
		$appPassword = $this->token($alice, IToken::PERMANENT_TOKEN, 'Desktop client');
		$other = $this->token($alice, IToken::TEMPORARY_TOKEN, 'Another browser');
		$fingerprinter = Server::get(Fingerprinter::class);
		$secrets = [
			'password' => self::PASSWORD,
			'wrong password' => $wrong,
			'password fingerprint' => bin2hex($fingerprinter->password($wrong)),
			'app password' => $appPassword['secret'],
			'other session id' => $other['secret'],
		];

		$this->failedLoginListener()->handle(new AnyLoginFailedEvent($alice->getUID(), $wrong));
		$this->failedLoginListener()->handle(new AnyLoginFailedEvent($alice->getUID(), $appPassword['secret']));
		$this->rememberDevice($alice);
		$secrets['device cookie'] = $this->deviceCookiesSet[0][0];
		$this->detection($alice, '203.0.113.10');
		Server::get(TrustedNetworks::class)->trust($alice->getUID(), SourceKey::fromIp('203.0.113.10'));
		$session = $this->startSession($alice);
		$secrets['session id'] = $session['secret'];
		Server::get(LoginHistoryMapper::class)->insert($alice->getUID(), time() - 60, SourceKey::fromIp('203.0.113.10'), 'Firefox/131.0', LoginHistory::METHOD_PASSWORD, false, 'none', null, $session['id']);

		$api = $this->controller();
		$responses = [
			'overview' => $api->overview()->getData(),
			'detections' => $api->detections()->getData(),
			'logins' => $api->logins()->getData(),
			'activity' => $api->activity()->getData(),
			'known devices' => $api->knownDevices()->getData(),
			'trusted networks' => $api->trustedNetworks()->getData(),
		];
		$this->assertSame(2, $responses['overview']['failedLogins']['total'], 'Both failures were counted');
		$this->assertCount(1, $responses['activity']['questions']);
		$this->assertEqualsCanonicalizing(['failed_logins', 'change', 'login'], array_values(array_unique(array_column($responses['activity']['items'], 'kind'))), 'The activity has the failures, the changes and the login');
		$responses['log out everywhere else'] = $api->logOutElsewhere()->getData();
		foreach ($responses as $name => $data) {
			$this->assertClean(json_encode($data, JSON_THROW_ON_ERROR), $secrets, 'response of ' . $name);
		}
		$result = $this->db->getQueryBuilder()->select('*')->from(UserDailyMapper::TABLE)->executeQuery();
		$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, 'failed-login counts');
		$result->closeCursor();
		$this->assertClean(is_file($logFile) ? (string)file_get_contents($logFile, false, null, $logOffset) : '', $secrets, 'server log');
	}

	private function failedLoginListener(): FailedLoginListener {
		return new FailedLoginListener(
			$this->appSettings(), $this->checkSettings(),
			$this->addresses(),
			Server::get(AttemptRecorder::class),
			Server::get(DecoyCredentialDetector::class),
			Server::get(ReservedNameDetector::class),
			Server::get(CredentialStuffingDetector::class),
			Server::get(PasswordSprayingDetector::class),
			Server::get(AccountUnderAttackDetector::class),
			Server::get(RiskScorer::class),
			Server::get(IUserManager::class),
			$this->request,
			Server::get(LoggerInterface::class),
			Server::get(FailedLoginStats::class),
			Server::get(\OCA\IntrusionDetection\Login\EmailAccounts::class),
		);
	}

	/**
	 * @param array<string, string> $secrets
	 */
	private function assertClean(string $text, array $secrets, string $where): void {
		foreach ($secrets as $name => $secret) {
			$this->assertStringNotContainsString($secret, $text, 'The ' . $name . ' is in the ' . $where);
		}
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}
}
