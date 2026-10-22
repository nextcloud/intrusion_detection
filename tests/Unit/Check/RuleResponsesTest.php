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
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\IDateTimeFormatter;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * Checks whose rules answer with different responses, and the counting
 * rules that keep outdated links from firing.
 */
class RuleResponsesTest extends TestCase {
	public function testShareRulesAboutOneAddressBlockAndTellTheAdmins(): void {
		$check = new ShareBruteforce(DateFormatter::using($this->createMock(IDateTimeFormatter::class)), $this->createMock(ContainerInterface::class));
		$all = [ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner];
		foreach ([ShareBruteforce::RULE_TOKENS, ShareBruteforce::RULE_TOKENS_NETWORK, ShareBruteforce::RULE_PASSWORD_SOURCE] as $rule) {
			$this->assertSame([ResponseType::Ban, ResponseType::NotifyAdmin], $check->responsesFor($this->draft(ShareBruteforce::ID, $rule), $all, []), $rule);
			$this->assertSame([ResponseType::Ban], $check->responsesFor($this->draft(ShareBruteforce::ID, $rule), [ResponseType::Ban], []), 'What the admin switched off stays off');
		}
		$this->assertSame([ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner], $check->responsesFor($this->draft(ShareBruteforce::ID, ShareBruteforce::RULE_PASSWORD_SHARE), $all, []));
		$this->assertSame([], $check->responsesFor($this->draft(ShareBruteforce::ID, ShareBruteforce::RULE_PASSWORD_SHARE), [ResponseType::Ban], []), 'A response the admin switched off stays off');
	}

	public function testUnknownLinksOfAPartnerServerAreReportedButNeverBlock(): void {
		$check = new ShareBruteforce(DateFormatter::using($this->createMock(IDateTimeFormatter::class)), $this->createMock(ContainerInterface::class));
		$partner = new DetectionDraft(ShareBruteforce::ID, facts: ['rule' => ShareBruteforce::RULE_TOKENS, 'federation' => true]);
		$this->assertSame([ResponseType::NotifyAdmin], $check->responsesFor($partner, [ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner], []));
	}

	public function testResetRules(): void {
		$check = new ResetProbing(DateFormatter::using($this->createMock(IDateTimeFormatter::class)));
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
			'two links never fire' => [2, 2, 2, false],
			'two kept links under a flood never fire' => [2, 20, 10, false],
			'three links at the lowest limit' => [3, 3, 3, true],
			'below the limit' => [9, 9, 10, false],
			'at the limit' => [10, 10, 10, true],
			'three kept links under a flood stand for thirty' => [3, 30, 30, true],
			'not enough even when scaled' => [3, 30, 31, false],
		];
	}

	#[DataProvider('tokenCounts')]
	public function testOutdatedLinksAreToleratedWhateverTheScale(int $raw, int $estimate, int $threshold, bool $fires): void {
		$this->assertSame($fires, ShareBruteforceDetector::reaches($raw, $estimate, $threshold));
	}

	public function testTheShareNoticeNamesTheWindowOfItsRule(): void {
		$links = $this->createMock(ShareLinks::class);
		$links->method('find')->willReturn(null);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturn($links);
		$check = new ShareBruteforce(DateFormatter::using($this->createMock(IDateTimeFormatter::class)), $container);
		$l = \OCP\Server::get(\OCP\L10N\IFactory::class)->get('intrusion_detection', 'en');
		$detection = new Detection();
		$detection->setExplanationData(['facts' => ['rule' => ShareBruteforce::RULE_PASSWORD_SOURCE, 'failures' => 5], 'thresholds' => ['password_source_window' => 600, 'password_share_window' => 3600]]);
		$this->assertStringContainsString('within 10 minutes', implode(' ', $check->userNotice($detection, $l)->message));
		$detection->setExplanationData(['facts' => ['rule' => ShareBruteforce::RULE_PASSWORD_SHARE, 'failures' => 20], 'thresholds' => ['password_source_window' => 600, 'password_share_window' => 3600]]);
		$this->assertStringContainsString('within 1 hour', implode(' ', $check->userNotice($detection, $l)->message));
	}

	private function draft(string $checkId, string $rule): DetectionDraft {
		return new DetectionDraft($checkId, facts: ['rule' => $rule]);
	}
}
