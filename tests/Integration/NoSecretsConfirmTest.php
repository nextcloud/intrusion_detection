<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\Authentication\Token\IToken;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 18 for the confirmation of sensitive actions and for
 * lockdown: the email codes, the password and the session ids appear in no
 * table, notification, audit or log line, narrative or session state.
 */
#[Group('DB')]
class NoSecretsConfirmTest extends SensitiveTestCase {
	public function testNoCodePasswordOrSessionIdLeaksAnywhere(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		$alice = $this->user('ids-secret-confirm', 'alice@example.com');
		$secrets = [
			'password' => self::PASSWORD,
			'first code' => '482915',
			'second code' => '730264',
			'third code' => '119838',
		];
		$sessionIds = [];
		Server::get(LockdownService::class)->start(3600, 'test', 'admin');

		// Confirmed after a wrong code and a new one.
		$sessionIds[] = $this->startSession($alice)['secret'];
		$this->confirmController()->show('/index.php/apps/files/');
		$stateWhileConfirming = json_encode($this->session->get(SessionState::SESSION_KEY), JSON_THROW_ON_ERROR);
		$this->confirmController()->confirm('000000');
		$this->confirmController()->resend();
		$this->confirmController()->confirm('730264');
		$this->assertSame('email_code', $this->state->get(SessionState::SENSITIVE)['by'] ?? null, 'The scenario confirmed the action');

		// Another session of the account is marked from elsewhere.
		$other = $this->token($alice, IToken::TEMPORARY_TOKEN, 'Chrome');
		$sessionIds[] = $other['secret'];
		$detection = new Detection();
		$detection->setId(1);
		$this->handler()->apply(new ResponseContext(new DetectionDraft(DirectoryScraping::ID, uid: $alice->getUID(), sessionTokenId: $other['id']), $detection, Server::get(CheckRegistry::class)->get(DirectoryScraping::ID), true));

		// Five wrong codes: told, ended.
		$this->session->clear();
		$sessionIds[] = $this->startSession($alice)['secret'];
		$this->confirmController()->show();
		for ($i = 0; $i < 5; $i++) {
			$this->confirmController()->confirm('111111');
		}
		$this->assertNull($this->sessionUser, 'The scenario ended the session');

		// Without email, waiting for an administrator.
		$bob = $this->user('ids-secret-confirm-bob', null);
		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$sessionIds[] = $this->startSession($bob)['secret'];
		$this->confirmController()->show();
		$this->confirmController()->approvalStatus();

		foreach ($sessionIds as $i => $id) {
			$secrets['session id ' . $i] = $id;
		}

		foreach (IntegrationTestCase::TABLES as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, $table);
			$result->closeCursor();
		}
		$this->assertNotSame([], CapturingNotificationApp::$notifications);
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare(clone $notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secrets, 'notification');
		}
		$codeMails = 0;
		foreach ($this->mailed as [, $mail]) {
			if ($mail->templateId === 'intrusion_detection.stepUpCode') {
				$codeMails++;
				$this->assertClean(json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR), ['password' => self::PASSWORD], 'code email');
				continue;
			}
			$this->assertClean(json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR), $secrets, 'email ' . $mail->templateId);
		}
		$this->assertSame(3, $codeMails, 'Two codes for the first confirmation, one for the second');
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach (Server::get(DetectionMapper::class)->findList(new DetectionFilter()) as $found) {
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($found, $l)->toArray()), $secrets, 'narrative');
		}
		$this->assertNotSame([], $this->audited);
		$this->assertClean(implode("\n", $this->audited), $secrets, 'audit log');
		$this->assertClean($stateWhileConfirming, $secrets, 'the session state while confirming');
		$this->assertStringContainsString('codeHash', $stateWhileConfirming, 'Only the hash is kept');
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
