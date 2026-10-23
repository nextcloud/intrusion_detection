<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 18 for the extra confirmation of logins: the email codes,
 * the password and the session id appear in no table, notification, log
 * line, narrative or session state. A code is only ever in its own email,
 * and only its hash is kept.
 */
#[Group('DB')]
class NoSecretsStepUpTest extends StepUpTestCase {
	public function testNoCodePasswordOrSessionIdLeaksAnywhere(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$alice = $this->user('ids-secret-stepup', 'alice@example.com');
		$secrets = [
			'password' => self::PASSWORD,
			'first code' => '482915',
			'second code' => '730264',
			'third code' => '119838',
		];
		$sessionIds = [];

		// Confirmed after a wrong code and a new one.
		$sessionIds[] = $this->startSession($alice)['secret'];
		$this->login($alice);
		$stateDuringStepUp = json_encode($this->session->get(SessionMarkers::SESSION_KEY), JSON_THROW_ON_ERROR);
		$this->verifyController()->confirm('000000');
		$this->verifyController()->resend();
		$this->verifyController()->confirm('730264');
		$this->assertNull($this->stepUp(), 'The scenario confirmed the login');

		// Five wrong codes: blocked, told, ended.
		$this->remoteAddress = '198.51.100.8';
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
		$sessionIds[] = $this->startSession($alice)['secret'];
		$this->login($alice);
		for ($i = 0; $i < 5; $i++) {
			$this->verifyController()->confirm('111111');
		}
		$this->assertNull($this->sessionUser, 'The scenario ended the login');

		// Without email: refused; with allow_notify: allowed; an app: refused.
		$bob = $this->user('ids-secret-stepup-bob', null);
		$sessionIds[] = $this->startSession($bob)['secret'];
		$this->login($bob);
		$this->verifyController()->show();
		$this->settingsEditor()->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'allow_notify');
		$sessionIds[] = $this->startSession($bob)['secret'];
		$this->login($bob);
		$this->rule()->check($this->state, RequestTarget::dav('GET', '/'));
		$this->settingsEditor()->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'refuse');
		$this->basicAuth($alice);
		$this->session->clear();
		$this->session->id = $sessionIds[] = bin2hex(random_bytes(32));
		$this->login($alice);

		foreach ($sessionIds as $i => $id) {
			$secrets['session id ' . $i] = $id;
		}

		foreach (IntegrationTestCase::tables() as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, $table);
			$result->closeCursor();
		}
		$this->assertNotSame([], CapturingNotificationApp::$notifications);
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare(clone $notification, 'en');
			$actions = array_map(static fn ($a): string => $a->getLink(), $prepared->getParsedActions());
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink() . implode(' ', $actions), $secrets, 'notification');
		}
		$codeMails = 0;
		foreach ($this->mailed as [, $mail]) {
			$text = json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR);
			if ($mail->templateId === 'intrusion_detection.stepUpCode') {
				$codeMails++;
				$this->assertClean($text, ['password' => self::PASSWORD], 'code email');
				$this->assertNull($mail->buttonUrl, 'No link in a code email');
				continue;
			}
			$this->assertClean($text, $secrets, 'email ' . $mail->templateId);
		}
		$this->assertSame(3, $codeMails, 'Two codes for the first login, one for the second');
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach (Server::get(DetectionMapper::class)->findList(new DetectionFilter()) as $detection) {
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray()), $secrets, 'narrative');
		}
		$this->assertClean($stateDuringStepUp, $secrets, 'the session state during the step-up');
		$this->assertStringContainsString('codeHash', $stateDuringStepUp, 'Only the hash is kept');
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
