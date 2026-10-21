<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\IConfig;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Concept section 18: passwords and their fingerprints must appear in no
 * detection, notification, email or log line. Fingerprints may only be in
 * the attempts table (for an hour) and as flags of sprayed passwords.
 */
#[Group('DB')]
class NoSecretsTest extends LoginFailureTestCase {
	/** Tables that may hold fingerprints, and in which column */
	private const FINGERPRINT_COLUMNS = ['ids_attempts' => ['pw_fp', 'name_hmac'], 'ids_flags' => ['flag_key']];

	/** @var list<string> */
	private array $logged = [];
	private int $logOffset = 0;

	protected function listenerLogger(): LoggerInterface {
		return new class($this->logged) extends AbstractLogger {
			/** @param list<string> $lines */
			public function __construct(
				private array &$lines,
			) {
			}

			public function log($level, string|\Stringable $message, array $context = []): void {
				$this->lines[] = $message . ' ' . json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
			}
		};
	}

	protected function setUp(): void {
		parent::setUp();
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
		$this->logOffset = is_file($this->logFile()) ? (int)filesize($this->logFile()) : 0;
	}

	public function testNoSecretReachesAnyTableNotificationEmailOrLog(): void {
		$secrets = [
			'stuffing' => 'Secret-Stuffing-Password-4b1f',
			'spraying' => 'Secret-Spraying-Password-77ac',
			'account' => 'Secret-Account-Password-c0de',
			'reserved' => 'Secret-Reserved-Password-9e9e',
			'app-password' => 'Qx7Kp-Zt3Wm-Rb8Nc-Jd2Hf-Ls9Gy',
		];
		$victim = 'ids-secret-victim-' . bin2hex(random_bytes(3));
		$this->user($victim);
		Server::get(ReservedNames::class)->add(['administrator'], 'test');

		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('198.51.100.7', 'stuffed' . $i, $secrets['stuffing']);
		}
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('203.0.113.' . $i, 'sprayed' . $i, $secrets['spraying']);
		}
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('192.0.2.' . ($i % 5 + 1), $victim, $secrets['account']);
		}
		$this->failLogin('198.51.100.99', 'administrator', $secrets['reserved']);
		$this->failLogin('198.51.100.98', 'someone', $secrets['app-password']);

		$this->assertGreaterThanOrEqual(4, $this->detections->count(new DetectionFilter()), 'Every scenario made a detection');
		$fingerprinter = Server::get(Fingerprinter::class);
		$fingerprints = [];
		foreach ($secrets as $secret) {
			foreach (array_merge($fingerprinter->passwordCandidates($secret), $fingerprinter->passwordFlagFingerprints($secret)) as $fingerprint) {
				$fingerprints[] = bin2hex($fingerprint);
			}
		}

		// Tables
		foreach (IntegrationTestCase::TABLES as $table) {
			foreach ($this->allRows($table) as $row) {
				$allowed = self::FINGERPRINT_COLUMNS[$table] ?? [];
				foreach ($row as $column => $value) {
					$value = (string)$value;
					foreach ($secrets as $secret) {
						$this->assertStringNotContainsString($secret, $value, $table . '.' . $column . ' holds a password');
					}
					if (!in_array($column, $allowed, true)) {
						foreach ($fingerprints as $fingerprint) {
							$this->assertStringNotContainsString($fingerprint, $value, $table . '.' . $column . ' holds a password fingerprint');
						}
					}
				}
			}
		}

		// Notifications, as stored and as shown
		$this->assertNotSame([], CapturingNotificationApp::$notifications, 'The admins were notified');
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secrets, $fingerprints, 'notification');
		}

		// Emails and narratives
		$admin = $this->createMock(IUser::class);
		$admin->method('getUID')->willReturn('admin');
		$admin->method('getEMailAddress')->willReturn('admin@example.com');
		foreach ($this->detections->findList(new DetectionFilter(limit: 100)) as $detection) {
			$mail = Server::get(AdminAlerts::class)->mailFor($detection, $admin);
			$this->assertClean(json_encode($mail, JSON_THROW_ON_ERROR) . json_encode(get_object_vars($mail)), $secrets, $fingerprints, 'email');
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray()), $secrets, $fingerprints, 'narrative');
		}

		// Logs
		$this->assertClean(implode("\n", $this->logged), $secrets, $fingerprints, 'listener log');
		$this->assertClean($this->newLogContent(), $secrets, $fingerprints, 'server log');
	}

	/**
	 * @param array<string, string> $secrets
	 * @param list<string> $fingerprints
	 */
	private function assertClean(string $text, array $secrets, array $fingerprints, string $where): void {
		foreach ($secrets as $name => $secret) {
			$this->assertStringNotContainsString($secret, $text, 'The ' . $name . ' password is in the ' . $where);
		}
		foreach ($fingerprints as $fingerprint) {
			$this->assertStringNotContainsString($fingerprint, $text, 'A password fingerprint is in the ' . $where);
		}
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}

	private function newLogContent(): string {
		if (!is_file($this->logFile())) {
			return '';
		}
		return (string)file_get_contents($this->logFile(), false, null, $this->logOffset);
	}
}
