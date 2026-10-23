<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingFacts;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingRule;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedFacts;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedRule;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmedFacts;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDenied;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDeniedFacts;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\IFacts;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCP\IDateTimeFormatter;
use Test\TestCase;

/**
 * Which responses the step-up checks run for which detection, and which
 * of them ask "Was this you?".
 */
class StepUpResponsesTest extends TestCase {
	public function testASprayedPasswordBlocksOnFailuresAndConfirmsOnSuccess(): void {
		$check = new PasswordSpraying($this->dates());
		$all = $check->definition()->defaultResponses;
		$this->assertSame([ResponseType::Ban, ResponseType::FlagPassword, ResponseType::NotifyAdmin], $check->responsesFor($this->draft(PasswordSpraying::ID, new PasswordSprayingFacts(rule: PasswordSprayingRule::Spray)), $all, []));
		$this->assertSame([ResponseType::Ban], $check->responsesFor($this->draft(PasswordSpraying::ID, new PasswordSprayingFacts(rule: PasswordSprayingRule::Flagged)), $all, []), 'An address joining a spray is only blocked');
		$this->assertSame(
			[ResponseType::StepUp, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			$check->responsesFor($this->draft(PasswordSpraying::ID, new PasswordSprayingFacts(rule: PasswordSprayingRule::Login)), $all, []),
			'A successful login is never blocked by this check',
		);
		$this->assertSame([ResponseType::StepUp], $check->responsesFor($this->draft(PasswordSpraying::ID, new PasswordSprayingFacts(rule: PasswordSprayingRule::Login)), [ResponseType::Ban, ResponseType::StepUp], []), 'What the admin switched off stays off');

		$this->assertTrue($check->asksWasThisYou($this->detection(['rule' => PasswordSprayingRule::Login->value])));
		$this->assertFalse($check->asksWasThisYou($this->detection(['rule' => PasswordSprayingRule::Spray->value])));
	}

	public function testOnlyWrongCodesBlockTheAddress(): void {
		$check = new StepUpFailed($this->dates());
		$all = $check->definition()->defaultResponses;
		$this->assertContains(ResponseType::Ban, $check->responsesFor($this->draft(StepUpFailed::ID, new StepUpFailedFacts(rule: StepUpFailedRule::Attempts)), $all, []));
		foreach ([StepUpFailedRule::Timeout, StepUpFailedRule::Resumed] as $rule) {
			$responses = $check->responsesFor($this->draft(StepUpFailed::ID, new StepUpFailedFacts(rule: $rule)), [...$all, ResponseType::FlagSource], []);
			$this->assertSame([ResponseType::KillSession, ResponseType::NotifyAdmin, ResponseType::NotifyUser], $responses, $rule->value);
		}
	}

	public function testThePoliciesChooseTheResponsesOfAnAllowedLogin(): void {
		$check = new StepUpUnconfirmed($this->dates());
		$all = $check->definition()->defaultResponses;
		$this->assertSame([ResponseType::NotifyAdmin, ResponseType::NotifyUser], $check->responsesFor($this->draft(StepUpUnconfirmed::ID, new StepUpUnconfirmedFacts(notify: true, forceChange: false)), $all, []));
		$this->assertSame([ResponseType::ForcePasswordChange], $check->responsesFor($this->draft(StepUpUnconfirmed::ID, new StepUpUnconfirmedFacts(notify: false, forceChange: true)), $all, []));
		$this->assertSame($all, $check->responsesFor($this->draft(StepUpUnconfirmed::ID, new StepUpUnconfirmedFacts(notify: true, forceChange: true)), $all, []));
	}

	public function testNoRequiresANewPasswordOnlyWhenThePasswordWasInvolved(): void {
		$check = new UserDenied($this->dates(), $this->createMock(CheckNames::class));
		$all = $check->definition()->defaultResponses;
		$this->assertContains(ResponseType::ForcePasswordChange, $check->responsesFor($this->draft(UserDenied::ID, new UserDeniedFacts(passwordInvolved: true)), $all, []));
		$this->assertNotContains(ResponseType::ForcePasswordChange, $check->responsesFor($this->draft(UserDenied::ID, new UserDeniedFacts(passwordInvolved: false)), $all, []));
		$this->assertContains(ResponseType::Ban, $check->responsesFor($this->draft(UserDenied::ID, new UserDeniedFacts()), $all, []));
		$this->assertNotContains(ResponseType::Ban, $check->responsesFor($this->draft(UserDenied::ID, new UserDeniedFacts(answeredFromSource: true)), $all, []), 'Never the address of the one who answers');
	}

	public function testTheStepUpChecksAreInternalAndAsk(): void {
		foreach ([new StepUpFailed($this->dates()), new StepUpRefused($this->dates()), new StepUpRefusedClient($this->dates()), new StepUpUnconfirmed($this->dates())] as $check) {
			$this->assertTrue($check->definition()->internal, $check->definition()->id);
			$this->assertTrue($check->asksWasThisYou($this->detection([])), $check->definition()->id);
		}
		$this->assertTrue((new UserDenied($this->dates(), $this->createMock(CheckNames::class)))->definition()->internal);
		$this->assertSame(
			[ResponseType::Ban, ResponseType::KillSession, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			(new StepUpFailed($this->dates()))->definition()->defaultResponses,
			'Concept section 14: kill session, ban, notify user and admin',
		);
	}

	private function dates(): DateFormatter {
		return DateFormatter::using($this->createMock(IDateTimeFormatter::class));
	}

	private function draft(string $checkId, IFacts $facts): DetectionDraft {
		return new DetectionDraft(checkId: $checkId, uid: 'alice', facts: $facts);
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	private function detection(array $facts): Detection {
		$detection = new Detection();
		$detection->setUid('alice');
		$detection->setExplanationData(['facts' => $facts]);
		return $detection;
	}
}
