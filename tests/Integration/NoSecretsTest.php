<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReports;
use OCA\IntrusionDetection\Incident\ReportFormat;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Digest;
use OCA\IntrusionDetection\Notification\DigestSchedule;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\IConfig;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Server;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\Share\IShare;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

/**
 * Concept section 18: passwords, decoy secrets, share tokens, reset inputs
 * and their fingerprints must appear in no detection, notification, email
 * or log line. Fingerprints may
 * only be in the attempts table (for an hour), as flags of sprayed
 * passwords, and as the decoys' own secret fingerprints.
 */
#[Group('DB')]
class NoSecretsTest extends LoginFailureTestCase {
	/** Tables that may hold fingerprints, and in which column */
	private const FINGERPRINT_COLUMNS = ['ids_attempts' => ['pw_fp', 'name_hmac'], 'ids_flags' => ['flag_key'], 'ids_decoys' => ['secret_hmac']];

	/** @var list<string> */
	private array $logged = [];
	private int $logOffset = 0;
	private ?string $adminEmail = null;

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
		// Admin alerts are emailed too: sending them, and failing to, must not leak either.
		$admin = Server::get(IUserManager::class)->get('admin');
		$this->adminEmail = $admin?->getSystemEMailAddress();
		$admin?->setSystemEMailAddress('admin@example.com');
		$this->settings->setGlobal(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, 'low');
	}

	protected function tearDown(): void {
		Server::get(IUserManager::class)->get('admin')?->setSystemEMailAddress($this->adminEmail ?? '');
		parent::tearDown();
	}

	public function testNoSecretReachesAnyTableNotificationEmailOrLog(): void {
		$secrets = [
			'stuffing' => 'Secret-Stuffing-Password-4b1f',
			'spraying' => 'Secret-Spraying-Password-77ac',
			'account' => 'Secret-Account-Password-c0de',
			'reserved' => 'Secret-Reserved-Password-9e9e',
			'app-password' => 'Qx7Kp-Zt3Wm-Rb8Nc-Jd2Hf-Ls9Gy',
		];
		[, $secrets['decoy-app-password']] = Server::get(DecoyService::class)->create('planted on nas01', 'decoy-svc', DecoyFormat::AppPassword, 'test');
		[, $secrets['decoy-token']] = Server::get(DecoyService::class)->create('planted in the wiki', null, DecoyFormat::Token, 'test');
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
		$this->failLogin('198.51.100.97', 'decoy-svc', 'Secret-Decoy-Name-Password-1d1d');
		$this->failLogin('198.51.100.96', 'admin', $secrets['decoy-app-password']);
		$this->failLogin('198.51.100.95', 'someone', $secrets['decoy-token']);

		$secrets['decoy-name-password'] = 'Secret-Decoy-Name-Password-1d1d';
		$this->assertGreaterThanOrEqual(7, $this->detections->count(new DetectionFilter()), 'Every scenario made a detection');
		$fingerprinter = Server::get(Fingerprinter::class);
		$fingerprints = [];
		foreach ($secrets as $secret) {
			foreach (array_merge($fingerprinter->passwordCandidates($secret), $fingerprinter->passwordFlagFingerprints($secret), [$fingerprinter->decoy($secret)]) as $fingerprint) {
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

		$this->assertEventsAndDigestClean($secrets, $fingerprints);
		$this->assertReportsClean([$victim, 'admin'], ['198.51.100.7', '198.51.100.96', '198.51.100.95', '203.0.113.1'], $secrets, $fingerprints);

		// Logs
		$this->assertClean(implode("\n", $this->logged), $secrets, $fingerprints, 'listener log');
		$this->assertClean($this->serverLogWithoutMailRecipients(), $secrets, $fingerprints, 'server log');
	}

	public function testShareTokensAndResetInputsAppearNowhere(): void {
		$tokens = [];
		for ($i = 1; $i <= 10; $i++) {
			$tokens['token' . $i] = 'SecretShareTok' . $i . 'x9q';
		}
		$owner = 'ids-secret-owner-' . bin2hex(random_bytes(3));
		$this->user($owner);
		$share = $this->createMock(IShare::class);
		$share->method('getId')->willReturn('987654');
		$share->method('getFullId')->willReturn('ocinternal:987654');
		$share->method('getShareType')->willReturn(IShare::TYPE_LINK);
		$share->method('getSharedBy')->willReturn($owner);
		$share->method('getShareOwner')->willReturn($owner);
		$share->method('getToken')->willReturn('SecretShareOfOwnerQ7');
		$tokens['real'] = 'SecretShareOfOwnerQ7';

		$victim = 'ids-secret-reset-' . bin2hex(random_bytes(3));
		$this->user($victim)->setSystemEMailAddress('secret-victim-mail-' . bin2hex(random_bytes(3)) . '@example.net');
		$inputs = ['victim-mail' => (string)Server::get(IUserManager::class)->get($victim)?->getEMailAddress()];
		for ($i = 1; $i <= 5; $i++) {
			$inputs['probe' . $i] = 'secret-probe-' . $i . '@example.org';
		}

		$shares = new ShareAccessFailedListener($this->settings, new RemoteAddressResolver($this->request, Server::get(IThrottler::class)), Server::get(AttemptRecorder::class), Server::get(ShareBruteforceDetector::class), $this->request, Server::get(IUserSession::class), $this->listenerLogger());
		$resets = new ResetRequestedListener($this->settings, new RemoteAddressResolver($this->request, Server::get(IThrottler::class)), Server::get(AttemptRecorder::class), Server::get(ResetProbingDetector::class), Server::get(ResetMailSuppressor::class), Server::get(IUserManager::class), $this->request, $this->listenerLogger());

		$this->remoteAddress = '198.51.100.7';
		for ($i = 1; $i <= 10; $i++) {
			$shares->handle(new ShareLinkAccessFailedEvent($tokens['token' . $i], null, ShareLinkAccessFailedEvent::REASON_NOT_FOUND));
		}
		for ($i = 1; $i <= 20; $i++) {
			$this->remoteAddress = '203.0.113.' . $i;
			$shares->handle(new ShareLinkAccessFailedEvent($tokens['real'], $share, ShareLinkAccessFailedEvent::REASON_WRONG_PASSWORD));
		}
		$this->remoteAddress = '198.51.100.8';
		for ($i = 1; $i <= 5; $i++) {
			$resets->handle(new PasswordResetRequestedEvent($inputs['probe' . $i]));
		}
		for ($i = 1; $i <= 5; $i++) {
			$this->remoteAddress = '192.0.2.' . $i;
			$resets->handle(new PasswordResetRequestedEvent($inputs['victim-mail']));
		}

		$found = array_count_values(array_map(static fn ($d): string => $d->getCheckId() . ':' . $d->getExplanationData()['facts']['rule'], $this->detections->findList(new DetectionFilter(limit: 100))));
		$this->assertSame(1, $found['share_bruteforce:tokens'] ?? 0);
		$this->assertSame(1, $found['share_bruteforce:password_share'] ?? 0);
		$this->assertSame(1, $found['reset_probing:enumeration'] ?? 0);
		$this->assertSame(1, $found['reset_probing:flood'] ?? 0);

		$secrets = $tokens + $inputs;
		$fingerprinter = Server::get(Fingerprinter::class);
		$fingerprints = [];
		foreach ($tokens as $token) {
			$fingerprints[] = bin2hex($fingerprinter->shareToken($token));
		}
		foreach ($inputs as $input) {
			$fingerprints[] = bin2hex($fingerprinter->name($input));
		}

		foreach (IntegrationTestCase::TABLES as $table) {
			foreach ($this->allRows($table) as $row) {
				foreach ($row as $column => $value) {
					$value = (string)$value;
					foreach ($secrets as $name => $secret) {
						$this->assertStringNotContainsStringIgnoringCase($secret, $value, $table . '.' . $column . ' holds the ' . $name);
					}
					if ($table !== 'ids_attempts' || $column !== 'name_hmac') {
						foreach ($fingerprints as $fingerprint) {
							$this->assertStringNotContainsString($fingerprint, $value, $table . '.' . $column . ' holds a fingerprint of a token or an input');
						}
					}
				}
			}
		}

		$this->assertNotSame([], CapturingNotificationApp::$notifications, 'The admins were notified');
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secrets, $fingerprints, 'notification');
		}
		$admin = $this->createMock(IUser::class);
		$admin->method('getUID')->willReturn('admin');
		$admin->method('getEMailAddress')->willReturn('admin@example.com');
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach ($this->detections->findList(new DetectionFilter(limit: 100)) as $detection) {
			$mail = Server::get(AdminAlerts::class)->mailFor($detection, $admin);
			$this->assertClean(json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR), $secrets, $fingerprints, 'email');
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray(), JSON_THROW_ON_ERROR), $secrets, $fingerprints, 'narrative');
			$check = Server::get(CheckRegistry::class)->check(Server::get(CheckRegistry::class)->classOf($detection->getCheckId()));
			if ($check instanceof IExplainsToUser && $detection->getUid() !== null) {
				$this->assertClean(json_encode(get_object_vars($check->userNotice($detection, $l)), JSON_THROW_ON_ERROR), $secrets, $fingerprints, 'user notice');
			}
		}
		$this->assertEventsAndDigestClean($secrets, $fingerprints);
		$this->assertReportsClean([$owner, $victim], ['198.51.100.7', '203.0.113.1', '198.51.100.8', '192.0.2.1'], $secrets, $fingerprints);
		$this->assertClean(implode("\n", $this->logged), $secrets, $fingerprints, 'listener log');
		$this->assertClean($this->serverLogWithoutMailRecipients(), $secrets, $fingerprints, 'server log');
	}

	/**
	 * The webhook payloads of every detection and block, and the digest of
	 * the period, carry none of the secrets.
	 *
	 * @param array<string, string> $secrets
	 * @param list<string> $fingerprints
	 */
	private function assertEventsAndDigestClean(array $secrets, array $fingerprints): void {
		$payloads = [];
		foreach ($this->detections->findList(new DetectionFilter(limit: 100)) as $detection) {
			$payloads[] = (new DetectionCreatedEvent($detection))->getWebhookSerializable();
		}
		$bans = Server::get(BanMapper::class)->findList(time(), true, 100);
		$this->assertNotSame([], $bans, 'Some scenario blocked an address');
		foreach ($bans as $ban) {
			$payloads[] = (new BanCreatedEvent($ban))->getWebhookSerializable();
			$payloads[] = (new BanLiftedEvent($ban))->getWebhookSerializable();
		}
		$this->assertClean(json_encode($payloads, JSON_THROW_ON_ERROR), $secrets, $fingerprints, 'webhook payload');

		$digest = Server::get(Digest::class);
		$content = $digest->content($digest->report(new DigestSchedule(DigestSchedule::WEEKLY, new \DateTimeZone('UTC')), time() + 60), 'en');
		$this->assertNotSame([], $content->details, 'The digest lists what happened');
		$text = json_encode(get_object_vars($content), JSON_THROW_ON_ERROR);
		foreach ($content->details as $card) {
			$text .= $card->getTitle() . $card->getSubtitle();
			foreach ($card->getRows() as $row) {
				$text .= $row->getLabel() . json_encode($row->getParts(), JSON_THROW_ON_ERROR);
			}
		}
		$this->assertClean($text, $secrets, $fingerprints, 'digest');
	}

	/**
	 * The incident reports of the accounts and addresses involved, as shown
	 * on the page, as JSON and as the printable page, carry none of the
	 * secrets.
	 *
	 * @param list<string> $accounts
	 * @param list<string> $addresses
	 * @param array<string, string> $secrets
	 * @param list<string> $fingerprints
	 */
	private function assertReportsClean(array $accounts, array $addresses, array $secrets, array $fingerprints): void {
		$reports = Server::get(IncidentReports::class);
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$queries = array_merge(
			array_map(static fn (string $uid): IncidentQuery => IncidentQuery::forUser($uid, null, null, time() + 1), $accounts),
			array_map(static fn (string $ip): IncidentQuery => IncidentQuery::forAddress($ip, null, null, time() + 1), $addresses),
		);
		$entries = 0;
		foreach ($queries as $query) {
			$report = $reports->report($query, 'admin', $l);
			$entries += count($report->entries);
			$this->assertClean(json_encode($report->toArray(), JSON_THROW_ON_ERROR), $secrets, $fingerprints, 'incident report of ' . $query->subject());
			foreach ([ReportFormat::Json, ReportFormat::Html] as $format) {
				$this->assertClean($reports->document($query, $format, 'admin', $l)['body'], $secrets, $fingerprints, $format->value . ' incident report of ' . $query->subject());
			}
		}
		$this->assertGreaterThan(0, $entries, 'the reports are not empty');
	}

	/**
	 * @param array<string, string> $secrets
	 * @param list<string> $fingerprints
	 */
	private function assertClean(string $text, array $secrets, array $fingerprints, string $where): void {
		foreach ($secrets as $name => $secret) {
			$this->assertStringNotContainsStringIgnoringCase($secret, $text, 'The ' . $name . ' secret is in the ' . $where);
		}
		foreach ($fingerprints as $fingerprint) {
			$this->assertStringNotContainsString($fingerprint, $text, 'A password fingerprint is in the ' . $where);
		}
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}

	/**
	 * The new server log lines, without core's "Sending mail to … failed"
	 * lines. Notifications correctly email users at their own address, and
	 * with no mail server in the test core logs that recipient: that is core
	 * naming a legitimate recipient, not the app storing an input.
	 */
	private function serverLogWithoutMailRecipients(): string {
		return implode("\n", array_filter(
			explode("\n", $this->newLogContent()),
			static fn (string $line): bool => !str_contains($line, '"message":"Sending mail to '),
		));
	}

	private function newLogContent(): string {
		if (!is_file($this->logFile())) {
			return '';
		}
		return (string)file_get_contents($this->logFile(), false, null, $this->logOffset);
	}
}
