<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The risk score reads the user agent of failed logins and keeps the name
 * of an attack tool. The password of those logins never ends up anywhere
 * (concept section 18).
 */
#[Group('DB')]
class NoSecretsRiskTest extends LoginFailureTestCase {
	private const SECRET = 'Unguessable-Secret-Pa55word-4711';

	public function testThePasswordAppearsInNoTableAndNoExplanation(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->userAgent = 'python-requests/2.31';
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i, self::SECRET);
		}
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$this->assertSame('python-requests', $detections[0]->getExplanationData()['facts']['risk']['parts'][0]['detail'], 'Only the tool name is kept');

		foreach (['ids_attempts', 'ids_detections', 'ids_flags', 'ids_bans', 'ids_alerts'] as $table) {
			$dump = json_encode($this->allRows($table), JSON_THROW_ON_ERROR);
			$this->assertStringNotContainsString(self::SECRET, $dump, $table);
			$this->assertStringNotContainsString(bin2hex(self::SECRET), $dump, $table);
		}
		$this->assertContains('python-requests', array_column($this->allRows('ids_flags'), 'reason'), 'The flag keeps the tool name');

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$detail = Server::get(DetectionPresenter::class)->detail($detections[0], $l);
		$this->assertStringNotContainsString(self::SECRET, json_encode($detail['risk'], JSON_THROW_ON_ERROR));
		$this->assertStringNotContainsString(self::SECRET, implode(' ', $detail['narrative']['happened']));
	}
}
