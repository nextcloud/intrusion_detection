<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use Test\TestCase;

/**
 * The one status vocabulary of a login's confirmation, and the one place
 * it is mapped to the values the session and the login history store.
 */
class LoginConfirmationTest extends TestCase {
	/**
	 * Every status: how much it proves, how the history stores it, and the
	 * marker it is kept in.
	 *
	 * @return array<string, array{LoginConfirmation, string, array{string, ?string}, ?string}>
	 */
	public static function statuses(): array {
		$stepUp = static fn (ConfirmationStatus $status): LoginConfirmation => LoginConfirmation::ofStepUp(new StepUpState('alice', $status, ['flagged_source'], 1, 2));
		return [
			'pending' => [$stepUp(ConfirmationStatus::Pending), SessionConfirmation::UNCONFIRMED, ['none', 'pending'], SessionMarkers::STEP_UP],
			'refused' => [$stepUp(ConfirmationStatus::Refused), SessionConfirmation::UNCONFIRMED, ['none', 'refused'], SessionMarkers::STEP_UP],
			'refused app' => [$stepUp(ConfirmationStatus::RefusedClient), SessionConfirmation::UNCONFIRMED, ['none', 'refused'], SessionMarkers::STEP_UP],
			'resumed' => [$stepUp(ConfirmationStatus::Resumed), SessionConfirmation::UNCONFIRMED, ['none', 'failed'], SessionMarkers::STEP_UP],
			'confirmed' => [LoginConfirmation::confirmed('alice', IConfirmationMethod::EMAIL_CODE, ['flagged_source'], 1), SessionConfirmation::PROVEN, ['email_code', 'confirmed'], SessionMarkers::CONFIRMATION],
			'allowed' => [LoginConfirmation::allowed('alice', ['flagged_source'], 1, false), SessionConfirmation::UNCONFIRMED, ['none', 'allowed'], SessionMarkers::CONFIRMATION],
			'proven' => [LoginConfirmation::proven('alice', IConfirmationMethod::SECOND_FACTOR, 1), SessionConfirmation::PROVEN, ['none', null], SessionMarkers::PROOF],
			'none' => [LoginConfirmation::none('alice'), SessionConfirmation::PASSWORD, ['none', null], null],
		];
	}

	/**
	 * @param array{string, ?string} $history
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('statuses')]
	public function testEachStatusMapsToTheStoredValues(LoginConfirmation $confirmation, string $level, array $history, ?string $marker): void {
		$this->assertSame($level, $confirmation->level());
		$this->assertSame($level === SessionConfirmation::UNCONFIRMED, $confirmation->isRisky());
		$this->assertSame($history, $confirmation->historyOutcome());
		$this->assertContains($history[0], LoginHistory::CONFIRMED_BY);
		if ($history[1] !== null) {
			$this->assertContains($history[1], LoginHistory::STEP_UP);
		}
		$stored = $confirmation->toMarker();
		$this->assertSame($marker, $stored[0] ?? null);
		if ($stored !== null) {
			$this->assertEquals($confirmation, LoginConfirmation::fromMarkers([$stored[0] => $stored[1]], 'alice'), 'Read back as it was kept');
		}
	}

	public function testEveryStatusIsCovered(): void {
		$covered = array_unique(array_map(static fn (array $row): ConfirmationStatus => $row[0]->status, array_values(self::statuses())), SORT_REGULAR);
		$this->assertCount(count(ConfirmationStatus::cases()), $covered);
	}

	public function testAStepUpIsAValue(): void {
		$state = new StepUpState('alice', ConfirmationStatus::Pending, ['flagged_source'], 1, 900, methods: ['email_code']);
		$changed = $state->withCode('hash', 600)->withAttempts(2)->withSecondFactorRequested()->withApproval('5', 1800);
		$this->assertNull($state->codeHash, 'The original is unchanged');
		$this->assertSame(['hash', 600, 2, true, '5', 1800], [$changed->codeHash, $changed->codeExpires, $changed->attempts, $changed->secondFactorRequested, $changed->approvalId, $changed->deadline]);
		$this->assertSame(1800, $changed->withApproval('6', 100)->deadline, 'An approval never shortens the wait');
		$this->assertSame(0, $changed->withCode(null, 600)->codeExpires);
	}
}
