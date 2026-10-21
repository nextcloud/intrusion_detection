<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;
use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCP\IDateTimeFormatter;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * Checks whose rules answer with different responses, and the counting
 * rules that keep outdated links from firing.
 */
class RuleResponsesTest extends TestCase {
	public function testShareRulesAboutOneAddressOnlyBlock(): void {
		$check = new ShareBruteforce(new DateFormatter($this->createMock(IDateTimeFormatter::class)), $this->createMock(ContainerInterface::class));
		$all = [ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner];
		foreach ([ShareBruteforce::RULE_TOKENS, ShareBruteforce::RULE_TOKENS_NETWORK, ShareBruteforce::RULE_PASSWORD_SOURCE] as $rule) {
			$this->assertSame([ResponseType::Ban], $check->responsesFor($this->draft(ShareBruteforce::ID, $rule), $all, []), $rule);
		}
		$this->assertSame([ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner], $check->responsesFor($this->draft(ShareBruteforce::ID, ShareBruteforce::RULE_PASSWORD_SHARE), $all, []));
		$this->assertSame([], $check->responsesFor($this->draft(ShareBruteforce::ID, ShareBruteforce::RULE_PASSWORD_SHARE), [ResponseType::Ban], []), 'A response the admin switched off stays off');
	}

	public function testResetRules(): void {
		$check = new ResetProbing(new DateFormatter($this->createMock(IDateTimeFormatter::class)));
		$all = [ResponseType::Ban, ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser];
		$this->assertSame([ResponseType::Ban], $check->responsesFor($this->draft(ResetProbing::ID, ResetProbing::RULE_ENUMERATION), $all, []));
		$this->assertSame([ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser], $check->responsesFor($this->draft(ResetProbing::ID, ResetProbing::RULE_FLOOD), $all, []));
	}

	/**
	 * @return array<string, array{Severity, bool, list<ResponseType>}>
	 */
	public static function loginFlowSeverities(): array {
		$all = [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser];
		return [
			'high revokes and tells' => [Severity::High, false, $all],
			'medium tells' => [Severity::Medium, false, [ResponseType::NotifyAdmin, ResponseType::NotifyUser]],
			'medium may revoke' => [Severity::Medium, true, $all],
			'low only records' => [Severity::Low, true, []],
		];
	}

	/**
	 * @param list<ResponseType> $expected
	 */
	#[DataProvider('loginFlowSeverities')]
	public function testLoginFlowResponsesFollowTheSeverity(Severity $severity, bool $mediumRevoke, array $expected): void {
		$check = new LoginFlowMismatch();
		$draft = new DetectionDraft(LoginFlowMismatch::ID, uid: 'alice', severity: $severity);
		$all = [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser];
		$this->assertSame($expected, $check->responsesFor($draft, $all, ['max_age' => 600, 'medium_revoke' => $mediumRevoke]));
	}

	public function testOnlyMediumLoginFlowDetectionsAskWasThisYou(): void {
		$check = new LoginFlowMismatch();
		foreach ([Severity::Low, Severity::Medium, Severity::High] as $severity) {
			$detection = new Detection();
			$detection->setSeverity($severity->value);
			$this->assertSame($severity === Severity::Medium, $check->asksWasThisYou($detection), $severity->value);
		}
	}

	/**
	 * @return array<string, array{int, int, int, bool}>
	 */
	public static function tokenCounts(): array {
		return [
			'two links never fire' => [2, 1, 2, false],
			'two kept links under a flood never fire' => [2, 10, 10, false],
			'three links at the lowest limit' => [3, 1, 3, true],
			'below the limit' => [9, 1, 10, false],
			'at the limit' => [10, 1, 10, true],
			'three kept links under a flood stand for thirty' => [3, 10, 30, true],
			'not enough even when scaled' => [3, 10, 31, false],
		];
	}

	#[DataProvider('tokenCounts')]
	public function testOutdatedLinksAreToleratedWhateverTheScale(int $raw, int $factor, int $threshold, bool $fires): void {
		$this->assertSame($fires, ShareBruteforceDetector::reaches($raw, $factor, $threshold));
	}

	private function draft(string $checkId, string $rule): DetectionDraft {
		return new DetectionDraft($checkId, facts: ['rule' => $rule]);
	}
}
