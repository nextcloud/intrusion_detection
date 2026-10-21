<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\ISession;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Mail\IEmailValidator;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The life of an email code: random, only its hash kept, valid for a
 * while, a limited number of tries and new codes.
 */
class EmailCodesTest extends TestCase {
	private int $now = 1_800_000_000;
	/** @var list<MailContent> */
	private array $sent = [];
	private bool $mailWorks = true;
	/** @var list<string> */
	private array $codes = ['482915', '730264', '119838', '650417', '004213'];
	private string $smtpMode = 'smtp';
	/** The tries the server counted; null: the session is not remembered there */
	private ?int $serverTries = null;

	public function testACodeIsRandomOnlyItsHashIsKeptAndItIsSentByEmail(): void {
		$random = $this->createMock(ISecureRandom::class);
		$random->expects($this->once())->method('generate')->with(6, ISecureRandom::CHAR_DIGITS)->willReturn('482915');
		$codes = $this->codes($random);
		$state = $this->state();
		$this->assertTrue($codes->issue($this->user(), $state));

		$this->assertNotNull($state->codeHash);
		$this->assertStringNotContainsString('482915', json_encode($state->toArray(), JSON_THROW_ON_ERROR), 'Never the code itself');
		$this->assertTrue(Server::get(IHasher::class)->verify('482915', $state->codeHash));
		$this->assertSame($this->now + 600, $state->codeExpires);
		$this->assertCount(1, $this->sent);
		$this->assertContains('482915', $this->sent[0]->paragraphs);
		$this->assertNull($this->sent[0]->buttonUrl, 'No link in the code email');
		$this->assertStringContainsString('198.51.100.7', implode(' ', $this->sent[0]->paragraphs));
	}

	public function testAFailedEmailKeepsNoCode(): void {
		$this->mailWorks = false;
		$state = $this->state();
		$this->assertFalse($this->codes()->issue($this->user(), $state));
		$this->assertNull($state->codeHash);
		$this->assertSame(EmailCodes::EXPIRED, $this->codes()->verify($state, '482915'));
	}

	public function testTheRightCodeWorksOnceWithSpacesOrDashes(): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		$this->assertSame(EmailCodes::VERIFIED, $codes->verify($state, ' 482-915 '));
		$this->assertNull($state->codeHash, 'Used up');
		$this->assertSame(EmailCodes::EXPIRED, $codes->verify($state, '482915'));
	}

	public function testTheServerCountsTheTriesSoThatParallelRequestsShareThem(): void {
		$this->serverTries = 0;
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		// Each request read the session before any of them saved it.
		$results = [];
		for ($i = 0; $i < 6; $i++) {
			$copy = StepUpState::fromArray($state->toArray());
			$this->assertNotNull($copy);
			$results[] = $codes->verify($copy, '000000');
		}
		$this->assertSame([EmailCodes::WRONG, EmailCodes::WRONG, EmailCodes::WRONG, EmailCodes::WRONG, EmailCodes::EXHAUSTED, EmailCodes::EXHAUSTED], $results);
		$this->assertSame(5, $this->serverTries, 'Never more than five');

		$copy = StepUpState::fromArray($state->toArray());
		$this->assertNotNull($copy);
		$this->assertSame(EmailCodes::EXHAUSTED, $codes->verify($copy, '482915'), 'Not even the right code after that');
		$this->assertSame(0, $codes->attemptsLeft($copy));
	}

	public function testMalformedAndExpiredCodesAreNotCountedOnTheServer(): void {
		$this->serverTries = 0;
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		$this->assertSame(EmailCodes::MALFORMED, $codes->verify($state, 'abc'));
		$this->now += 601;
		$this->assertSame(EmailCodes::EXPIRED, $codes->verify($state, '482915'));
		$this->assertSame(0, $this->serverTries);
	}

	public function testACodeExpires(): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		$this->now += 600;
		$this->assertSame(EmailCodes::EXPIRED, $codes->verify($state, '482915'));
		$this->assertSame(0, $state->attempts, 'An expired code is no guess');
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function malformed(): array {
		return [
			'empty' => [''],
			'letters' => ['abcdef'],
			'too short' => ['48291'],
			'too long' => ['4829150'],
		];
	}

	#[DataProvider('malformed')]
	public function testMalformedInputIsNotCountedAsATry(string $input): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		$this->assertSame(EmailCodes::MALFORMED, $codes->verify($state, $input));
		$this->assertSame(0, $state->attempts);
	}

	public function testFiveWrongCodesUseUpTheTries(): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		for ($i = 1; $i < EmailCodes::MAX_ATTEMPTS; $i++) {
			$this->assertSame(EmailCodes::WRONG, $codes->verify($state, '000000'));
			$this->assertSame(EmailCodes::MAX_ATTEMPTS - $i, $codes->attemptsLeft($state));
		}
		$this->assertSame(EmailCodes::EXHAUSTED, $codes->verify($state, '000000'));
		$this->assertSame(EmailCodes::EXHAUSTED, $codes->verify($state, '482915'), 'Not even the right code after that');
	}

	public function testANewCodeReplacesTheOldOneAndTheTriesStay(): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		$codes->verify($state, '000000');
		$this->assertTrue($codes->resend($this->user(), $state));
		$this->assertSame(EmailCodes::WRONG, $codes->verify($state, '482915'), 'The first code no longer works');
		$this->assertSame(2, $state->attempts, 'A new code does not give new tries');
		$this->assertSame(EmailCodes::VERIFIED, $codes->verify($state, '730264'));
	}

	public function testAtMostThreeNewCodesPerTenMinutes(): void {
		$codes = $this->codes();
		$state = $this->state();
		$codes->issue($this->user(), $state);
		for ($i = 0; $i < EmailCodes::MAX_RESENDS; $i++) {
			$this->now += 60;
			$this->assertTrue($codes->resend($this->user(), $state));
		}
		$this->assertFalse($codes->canResend($state));
		$this->assertFalse($codes->resend($this->user(), $state));
		$this->assertCount(1 + EmailCodes::MAX_RESENDS, $this->sent);

		$this->now += EmailCodes::RESEND_WINDOW - 3 * 60 + 61;
		$this->assertTrue($codes->canResend($state), 'The window moves on');
	}

	public function testOnlyAccountsWithAValidAddressOnAServerThatSendsMail(): void {
		$this->assertTrue($this->codes()->isAvailable($this->user()));
		$this->assertFalse($this->codes()->isAvailable($this->user('')), 'No email address');
		$this->assertFalse($this->codes()->isAvailable($this->user('not an address')));
		$this->smtpMode = 'null';
		$this->assertFalse($this->codes()->isAvailable($this->user()), 'The server does not send mail');
	}

	/**
	 * @return array<string, array{string, string}>
	 */
	public static function addresses(): array {
		return [
			'plain' => ['frank@example.com', 'f***@example.com'],
			'long local part' => ['first.last+tag@mail.example.org', 'f***@mail.example.org'],
			'unicode' => ['éva@example.com', 'é***@example.com'],
			'no at' => ['frank', '***'],
		];
	}

	#[DataProvider('addresses')]
	public function testAddressesAreMasked(string $address, string $masked): void {
		$this->assertSame($masked, EmailCodes::mask($address));
	}

	private function state(): StepUpState {
		return new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], $this->now, $this->now + 900, '198.51.100.7', ['email_code']);
	}

	private function user(string $address = 'alice@example.com'): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$user->method('getEMailAddress')->willReturn($address);
		return $user;
	}

	private function codes(?ISecureRandom $random = null): EmailCodes {
		if ($random === null) {
			$random = $this->createMock(ISecureRandom::class);
			$random->method('generate')->willReturnCallback(function (): string {
				return array_shift($this->codes) ?? '999999';
			});
		}
		$mails = $this->createMock(Mails::class);
		$mails->method('send')->willReturnCallback(function (IUser $user, MailContent $content): bool {
			if ($this->mailWorks) {
				$this->sent[] = $content;
			}
			return $this->mailWorks;
		});
		$messages = $this->createMock(UserMessages::class);
		$messages->method('l10nFor')->willReturn(Server::get(IFactory::class)->get('intrusion_detection', 'en'));
		$settings = $this->createMock(Settings::class);
		$settings->method('getInt')->willReturnCallback(static fn (string $name): int => $name === GlobalSettings::STEP_UP_CODE_TTL ? 600 : 0);
		$validator = $this->createMock(IEmailValidator::class);
		$validator->method('isValid')->willReturnCallback(static fn (string $a): bool => str_contains($a, '@'));
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default): string => $key === 'mail_smtpmode' ? $this->smtpMode : $default);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$sessions = $this->createMock(UnconfirmedSessions::class);
		$sessions->method('takeCodeAttempt')->willReturnCallback(function (string $sessionId, int $max): ?int {
			if ($this->serverTries === null) {
				return 0;
			}
			return $this->serverTries < $max ? ++$this->serverTries : null;
		});
		$session = $this->createMock(ISession::class);
		$session->method('getId')->willReturn('session-id');
		return new EmailCodes($random, Server::get(IHasher::class), $mails, $messages, $settings, $validator, $config, $time, $sessions, $session);
	}
}
