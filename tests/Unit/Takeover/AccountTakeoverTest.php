<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Takeover;

use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover\AccountTakeover;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
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
		$this->assertStringContainsString('{retention_detections_days}', $texts->data);
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
	}

	private function dates(): DateFormatter {
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatDateTime')->willReturnCallback(static fn ($t): string => gmdate('Y-m-d H:i', is_int($t) ? $t : 0));
		$formatter->method('formatTime')->willReturnCallback(static fn ($t): string => gmdate('H:i', is_int($t) ? $t : 0));
		return DateFormatter::using($formatter);
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
		$detection->setCreatedTime(1792560200);
		$detection->setLastSeenAt(1792560200);
		$detection->setHits(1);
		$detection->setExplanationData(['facts' => $facts, 'thresholds' => $thresholds]);
		return $detection;
	}
}
