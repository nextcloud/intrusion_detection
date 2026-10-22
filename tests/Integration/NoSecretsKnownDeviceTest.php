<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 18 for known devices and the login history: the device
 * cookie, the password and the session ids appear in no table,
 * notification, log line, list or session state. Only a keyed fingerprint
 * of the cookie is stored.
 */
#[Group('DB')]
class NoSecretsKnownDeviceTest extends StepUpTestCase {
	public function testTheDeviceCookieLeaksNowhere(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$alice = $this->user('ids-secret-device', 'alice@example.com');
		$secrets = ['password' => self::PASSWORD];

		$secrets['session 1'] = $this->startSession($alice)['secret'];
		$this->login($alice);
		$this->verifyController()->confirm('482915', '', '1');
		$this->nextRequest();
		$this->session->clear();
		$secrets['session 2'] = $this->startSession($alice)['secret'];
		$this->login($alice);
		$this->assertSame('known_device', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null, 'The scenario used the device');
		$state = json_encode($this->session->get(SessionState::SESSION_KEY), JSON_THROW_ON_ERROR);
		$list = json_encode($this->knownDevices()->forUser($alice->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en')), JSON_THROW_ON_ERROR);
		$this->knownDevices()->remember($alice, null, null);
		$this->knownDevices()->forgetCurrentDevice($alice->getUID(), 1);

		$this->assertNotSame([], $this->deviceCookiesSet);
		foreach ($this->deviceCookiesSet as $i => [$value]) {
			if ($value !== '') {
				$secrets['device cookie ' . $i] = $value;
			}
		}

		foreach (IntegrationTestCase::tables() as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, $table);
			$result->closeCursor();
		}
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare(clone $notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage(), $secrets, 'notification');
		}
		$this->assertClean($state, $secrets, 'the session state');
		$this->assertClean($list, $secrets, 'the list of devices');
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

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}
}
