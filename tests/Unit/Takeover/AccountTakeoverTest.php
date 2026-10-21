<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Takeover;

use OCA\IntrusionDetection\Check\Checks\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

/**
 * The definition and texts of the takeover check and of the lock it can
 * lead to (concept sections 10.14, 14 and 16.3).
 */
class AccountTakeoverTest extends TestCase {
	public function testTheDefaultsFollowTheConcept(): void {
		$definition = (new AccountTakeover($this->dates()))->definition();
		$this->assertSame(Mode::Protect, $definition->defaultMode);
		$this->assertSame(Severity::High, $definition->severity);
		$this->assertSame([ResponseType::LockLink, ResponseType::NotifyAdmin, ResponseType::NotifyUser], $definition->defaultResponses);
		$this->assertTrue($definition->allowsResponse(ResponseType::KillSession), 'Optional, off by default');
		$this->assertSame(3600, $definition->param(AccountTakeover::PARAM_WINDOW)->default);
		$this->assertSame(3, $definition->param(AccountTakeover::PARAM_MIN_POINTS)->default);
		$this->assertSame(1800, $definition->param(AccountTakeover::PARAM_WINDOW_ANY)->default);
		$this->assertSame(5, $definition->param(AccountTakeover::PARAM_MIN_POINTS_ANY)->default);
		$this->assertSame(['email_changed' => 2, 'password_changed' => 1, 'second_factor_added' => 1, 'second_factor_removed' => 3, 'second_factor_disabled' => 3, 'app_password_created' => 1, 'device_connected' => 1], AccountTakeover::DEFAULT_POINTS);
	}

	public function testEveryCountedKindHasItsPointsParameter(): void {
		$definition = (new AccountTakeover($this->dates()))->definition();
		foreach (SecurityChangeType::cases() as $type) {
			$param = $type->pointsParam();
			if ($type === SecurityChangeType::AppPasswordRevoked) {
				$this->assertNull($param, 'A revoked app password never counts');
				continue;
			}
			$this->assertTrue($definition->hasParam((string)$param), $type->value);
		}
	}

	public function testTheDecidesSentenceNamesEveryParameter(): void {
		$definition = (new AccountTakeover($this->dates()))->definition();
		$texts = $definition->texts($this->l());
		foreach ($definition->params as $param) {
			$this->assertStringContainsString('{' . $param->name . '}', $texts->decides, $param->name);
		}
		$this->assertStringContainsString('{history_retention_days}', $texts->data);
	}

	public function testTheNarrativeTellsTheChangesAndTheLimits(): void {
		$detection = $this->detection([
			'rules' => [AccountTakeover::RULE_RISKY_LOGIN],
			'sessionPoints' => 3,
			'riskyLoginAt' => 1792560000,
			'userHasEmail' => false,
			'changes' => [
				['type' => 'email_changed', 'at' => 1792560100, 'points' => 2, 'ip' => '203.0.113.7', 'old' => 'a***@example.com', 'new' => 'e***@evil.example'],
				['type' => 'app_password_created', 'at' => 1792560200, 'points' => 1, 'ip' => null, 'old' => null, 'new' => null],
			],
		], [AccountTakeover::PARAM_MIN_POINTS => 3, AccountTakeover::PARAM_WINDOW => 3600]);
		$text = implode("\n", (new AccountTakeover($this->dates()))->narrative($detection, $this->l()));
		$this->assertStringContainsString('Email address changed from a***@example.com to e***@evil.example', $text);
		$this->assertStringContainsString('from 203.0.113.7 (2 points)', $text);
		$this->assertStringContainsString('App password created', $text);
		$this->assertStringContainsString('Together they count 3 points. The limit at that time was 3 points within 1 hour after a risky login.', $text);
		$this->assertStringContainsString('has no email address now', $text);
	}

	public function testTheUserIsAskedWithoutThresholds(): void {
		$detection = $this->detection(['changes' => [['type' => 'second_factor_disabled'], ['type' => 'email_changed']]], [AccountTakeover::PARAM_MIN_POINTS => 3]);
		$check = new AccountTakeover($this->dates());
		$this->assertTrue($check->asksWasThisYou($detection));
		$notice = $check->userNotice($detection, $this->l());
		$text = implode(' ', [...$notice->message, ...$notice->advice]);
		$this->assertStringContainsString('Two-factor authentication turned off, Email address changed', $text);
		$this->assertStringNotContainsString('points', $text);
	}

	public function testTheLockIsCriticalAndInternal(): void {
		$check = new AccountLocked($this->dates());
		$definition = $check->definition();
		$this->assertTrue($definition->internal);
		$this->assertSame(Severity::Critical, $definition->severity);
		$this->assertSame([ResponseType::NotifyAdmin], $definition->defaultResponses);
		$detection = $this->detection(['sentTo' => 'a***@example.com', 'newAddress' => 'e***@evil.example', 'changedAt' => 1792560100, 'changedFrom' => '203.0.113.7', 'tokensEnded' => 3], []);
		$text = implode("\n", $check->narrative($detection, $this->l()));
		$this->assertStringContainsString('locked by the owner of the previous email address a***@example.com', $text);
		$this->assertStringContainsString('changed to e***@evil.example', $text);
		$this->assertStringContainsString('3 sessions and app passwords were ended', $text);
	}

	private function dates(): DateFormatter {
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatDateTime')->willReturnCallback(static fn ($t): string => gmdate('Y-m-d H:i', is_int($t) ? $t : 0));
		$formatter->method('formatTime')->willReturnCallback(static fn ($t): string => gmdate('H:i', is_int($t) ? $t : 0));
		return new DateFormatter($formatter);
	}

	private function l(): IL10N {
		return Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	/**
	 * @param array<string, mixed> $facts
	 * @param array<string, int> $thresholds
	 */
	private function detection(array $facts, array $thresholds): Detection {
		$detection = new Detection();
		$detection->setUid('alice');
		$detection->setCheckId(AccountTakeover::ID);
		$detection->setCreatedAt(1792560200);
		$detection->setLastSeenAt(1792560200);
		$detection->setHits(1);
		$detection->setExplanationData(['facts' => $facts, 'thresholds' => $thresholds]);
		return $detection;
	}
}
