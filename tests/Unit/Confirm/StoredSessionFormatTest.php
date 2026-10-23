<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OC\Session\Memory;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Takeover\Signals\UnconfirmedLoginSignal;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ISession;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * A login's confirmation as sessions keep it. Remembered sessions live for
 * weeks, so what is stored here must stay readable: these are literal
 * copies of what the app writes into the PHP session.
 */
class StoredSessionFormatTest extends TestCase {
	private const SESSION_TOKEN = 7;

	/**
	 * @return array<string, mixed>
	 */
	private static function pending(): array {
		return [
			'uid' => 'alice',
			'status' => 'pending',
			'policies' => ['flagged_source', 'protected_account'],
			'started' => 1_800_000_000,
			'deadline' => 1_800_000_900,
			'ip' => '198.51.100.7',
			'methods' => ['email_code', 'admin_approval'],
			'codeHash' => '3|$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$aGFzaA',
			'codeExpires' => 1_800_000_600,
			'attempts' => 2,
			'resends' => [1_800_000_100],
			'reference' => null,
			'detection' => null,
			'secondFactor' => false,
			'approval' => 41,
		];
	}

	public function testAStoredStepUpReadsBackUnchanged(): void {
		$refused = array_replace(self::pending(), ['status' => 'refused', 'deadline' => 0, 'methods' => [], 'codeHash' => null, 'codeExpires' => 0, 'attempts' => 0, 'resends' => [], 'reference' => 'SAAA-AAB3', 'detection' => 98, 'approval' => null]);
		foreach ([self::pending(), $refused] as $stored) {
			$this->assertSame($stored, StepUpState::fromArray($stored)?->toArray());
		}
	}

	/**
	 * The markers, then what the login proved, and the risky login the
	 * takeover check sees: when, and for which reasons.
	 *
	 * @return iterable<string, array{0: array<string, array<string, mixed>>, 1: string, 2: ?array{int, list<string>}}>
	 */
	public static function sessions(): iterable {
		yield 'nothing' => [[], 'password', null];
		yield 'waiting for its confirmation' => [['step_up' => self::pending()], 'unconfirmed', [1_800_000_000, ['flagged_source', 'protected_account']]];
		yield 'refused' => [['step_up' => ['status' => 'refused', 'deadline' => 0] + self::pending()], 'unconfirmed', [1_800_000_000, ['flagged_source', 'protected_account']]];
		yield 'an app, refused' => [['step_up' => ['status' => 'refused_client', 'deadline' => 0] + self::pending()], 'unconfirmed', [1_800_000_000, ['flagged_source', 'protected_account']]];
		yield 'came back unconfirmed' => [['step_up' => ['status' => 'resumed', 'policies' => []] + self::pending()], 'unconfirmed', [1_800_000_000, []]];
		yield 'confirmed with the email code' => [['confirmation' => ['uid' => 'alice', 'by' => 'email_code', 'policies' => ['flagged_source'], 'at' => 1_800_000_300]], 'proven', null];
		yield 'confirmed by an administrator' => [['confirmation' => ['uid' => 'alice', 'by' => 'admin_approval', 'policies' => ['flagged_source'], 'at' => 1_800_000_300]], 'proven', null];
		yield 'let in without a confirmation' => [['confirmation' => ['uid' => 'alice', 'by' => 'none', 'policies' => ['protected_account'], 'at' => 1_800_000_300]], 'unconfirmed', [1_800_000_300, ['protected_account']]];
		yield 'an app let in without a confirmation' => [['confirmation' => ['uid' => 'alice', 'by' => 'none', 'policies' => ['protected_account'], 'at' => 1_800_000_300, 'client' => true]], 'unconfirmed', [1_800_000_300, ['protected_account']]];
		yield 'a second factor without a reason' => [['proof' => ['uid' => 'alice', 'by' => 'second_factor', 'at' => 1_800_000_300]], 'proven', null];
		yield 'a known device without a reason' => [['proof' => ['uid' => 'alice', 'by' => 'known_device', 'at' => 1_800_000_300]], 'proven', null];
		yield 'let in unconfirmed, then a second factor' => [[
			'confirmation' => ['uid' => 'alice', 'by' => 'none', 'policies' => ['protected_account'], 'at' => 1_800_000_300],
			'proof' => ['uid' => 'alice', 'by' => 'second_factor', 'at' => 1_800_000_400],
		], 'unconfirmed', [1_800_000_300, ['protected_account']]];
		yield 'confirmed, then waiting again' => [[
			'step_up' => self::pending(),
			'confirmation' => ['uid' => 'alice', 'by' => 'email_code', 'policies' => ['flagged_source'], 'at' => 1_800_000_300],
		], 'unconfirmed', [1_800_000_000, ['flagged_source', 'protected_account']]];
		yield 'markers of another account' => [[
			'step_up' => ['uid' => 'mallory'] + self::pending(),
			'confirmation' => ['uid' => 'mallory', 'by' => 'none', 'policies' => [], 'at' => 1_800_000_300],
		], 'password', null];
		yield 'a confirmation of an unknown kind' => [['confirmation' => ['uid' => 'alice', 'by' => 'carrier_pigeon', 'policies' => [], 'at' => 1_800_000_300]], 'password', null];
	}

	/**
	 * @param array<string, array<string, mixed>> $markers
	 * @param ?array{int, list<string>} $risky
	 */
	#[DataProvider('sessions')]
	public function testWhatAStoredSessionProved(array $markers, string $level, ?array $risky): void {
		$session = new Memory();
		$session->set(SessionState::SESSION_KEY, $markers);
		$this->assertSame($level, $this->level($session));
		$login = $this->riskyLogin($session);
		$this->assertSame($risky, $login === null ? null : [$login->at, $login->policies]);
	}

	private function level(ISession $session): string {
		$state = new SessionState($session, $this->createMock(LoggerInterface::class));
		return (new SessionConfirmation($state, $session, $this->createMock(ITimeFactory::class)))->level('alice');
	}

	private function riskyLogin(ISession $session): ?\OCA\IntrusionDetection\Takeover\RiskyLogin {
		$state = new SessionState($session, $this->createMock(LoggerInterface::class));
		$current = $this->createMock(CurrentSession::class);
		$current->method('tokenId')->willReturn(self::SESSION_TOKEN);
		return (new UnconfirmedLoginSignal($state, $current))->riskyLogin('alice', self::SESSION_TOKEN);
	}
}
