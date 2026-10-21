<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Personal;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IProvidesPersonalSettings;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The status line in each state, and when the hint for accounts without an
 * email address or second factor is shown.
 */
class PersonalOverviewTest extends TestCase {
	private const NOW = 1792576800;

	/** @var list<Detection> */
	private array $detections = [];
	/** @var array<int, bool> detection id => open question */
	private array $open = [];
	private bool $passwordChange = false;
	private ?int $protectedUntil = null;
	private string $email = 'alice@example.com';
	private bool $secondFactor = false;
	/** @var list<IProvider> */
	private array $providers = [];
	private bool $providersFail = false;

	public function testCalmWhenNothingHappened(): void {
		$status = $this->statusFor(0);
		$this->assertSame('ok', $status['level']);
		$this->assertSame('No unusual activity in the last 30 days', $status['headline']);
		$this->assertSame([], $status['items']);
	}

	public function testFailedLoginsAloneStayCalmButAreNamed(): void {
		$status = $this->statusFor(4);
		$this->assertSame('ok', $status['level']);
		$this->assertSame('No unusual activity in the last 30 days', $status['headline']);
		$this->assertSame(['failed_logins'], array_column($status['items'], 'id'));
		$this->assertSame('4 failed logins in the last 30 days.', $status['items'][0]['text']);
	}

	public function testHandledEventsAreInformation(): void {
		$this->detection(1, self::NOW - 3 * 86400, false);
		$this->detection(2, self::NOW - 40 * 86400, false);
		$status = $this->statusFor(0);
		$this->assertSame('info', $status['level']);
		$this->assertSame('1 security event in the last 30 days. What happened and what Nextcloud did is listed below.', $status['headline'], 'Older events are not recent');
	}

	public function testOpenQuestionsComeFirst(): void {
		$this->detection(1, self::NOW - 3600, true);
		$this->detection(2, self::NOW - 50 * 86400, true);
		$this->passwordChange = true;
		$status = $this->statusFor(2);
		$this->assertSame('warning', $status['level']);
		$this->assertSame('2 events need your answer: was this you?', $status['headline'], 'Every open question counts, also older ones');
		$this->assertSame(['password_change', 'events', 'failed_logins'], array_column($status['items'], 'id'));
	}

	public function testARequiredPasswordChangeIsNamed(): void {
		$this->passwordChange = true;
		$status = $this->statusFor(0);
		$this->assertSame('warning', $status['level']);
		$this->assertSame('You will be asked to choose a new password the next time you log in.', $status['headline']);
	}

	public function testExtraProtectionSaysUntilWhenAndWhyInPlainWords(): void {
		$this->protectedUntil = self::NOW + 3600;
		$status = $this->statusFor(12);
		$this->assertSame('warning', $status['level']);
		$this->assertSame('Your account is under extra protection until time:' . (self::NOW + 3600) . ' because someone is trying to guess your password. Until then, logins with your password need an extra confirmation.', $status['headline']);
		$this->assertSame(['failed_logins'], array_column($status['items'], 'id'));

		$this->protectedUntil = self::NOW + 2 * 86400;
		$this->assertStringContainsString('until date:' . (self::NOW + 2 * 86400) . ' because', $this->statusFor(0)['headline'], 'Another day comes with its date');
	}

	public function testTheStatusNeverNamesThresholdsOrOtherAccounts(): void {
		$this->detection(1, self::NOW - 3600, true);
		$this->protectedUntil = self::NOW + 3600;
		$json = strtolower(json_encode($this->statusFor(30), JSON_THROW_ON_ERROR));
		foreach (['limit', 'threshold', 'admin', 'bob'] as $word) {
			$this->assertStringNotContainsString($word, $json);
		}
	}

	public function testNoHintWithAnEmailAddressOrASecondFactor(): void {
		$this->providers = [$this->provider('totp')];
		$this->assertNull($this->overview()->emailHint($this->user()));
		$this->email = '';
		$this->secondFactor = true;
		$this->assertNull($this->overview()->emailHint($this->user()));
	}

	public function testTheHintOffersASecondFactorOnlyWhenOneCanBeSetUp(): void {
		$this->email = '';
		$this->providers = [$this->provider('backup_codes')];
		$this->assertSame(['emailUrl' => 'profile-contact', 'secondFactorUrl' => null], $this->overview()->emailHint($this->user()), 'Backup codes alone are no second factor');

		$this->providers = [$this->provider('backup_codes'), $this->provider('totp')];
		$this->assertSame(['emailUrl' => 'profile-contact', 'secondFactorUrl' => 'security#two-factor-auth'], $this->overview()->emailHint($this->user()));

		$this->providersFail = true;
		$this->assertNull($this->overview()->emailHint($this->user())['secondFactorUrl'] ?? null, 'A broken provider app hides the button');
	}

	/**
	 * @return array{level: string, headline: string, items: list<array{id: string, level: string, text: string, at: ?int}>}
	 */
	private function statusFor(int $failedLogins): array {
		return $this->overview()->status($this->user(), $this->l(), new \DateTimeZone('UTC'), $failedLogins);
	}

	private function detection(int $id, int $createdAt, bool $open): void {
		$detection = new Detection();
		$detection->setId($id);
		$detection->setCreatedAt($createdAt);
		$this->detections[] = $detection;
		$this->open[$id] = $open;
	}

	private function provider(string $id): IProvider {
		$provider = $id === 'backup_codes'
			? $this->createMock(IProvider::class)
			: $this->createMock(IProvidesPersonalSettings::class);
		$provider->method('getId')->willReturn($id);
		return $provider;
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$user->method('getEMailAddress')->willReturn($this->email === '' ? null : $this->email);
		return $user;
	}

	private function l(): IL10N {
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnCallback(static fn (string $text, array $parameters = []): string => vsprintf($text, $parameters));
		$l->method('n')->willReturnCallback(static fn (string $singular, string $plural, int $count): string => str_replace('%n', (string)$count, $count === 1 ? $singular : $plural));
		return $l;
	}

	private function overview(): PersonalOverview {
		$mapper = $this->createMock(DetectionMapper::class);
		$mapper->method('findList')->willReturnCallback(fn (): array => $this->detections);
		$questions = $this->createMock(Questions::class);
		$questions->method('isOpen')->willReturnCallback(fn (Detection $d): bool => $this->open[$d->getId()] ?? false);
		$flag = $this->createMock(PasswordChangeFlag::class);
		$flag->method('isRequired')->willReturnCallback(fn (): bool => $this->passwordChange);
		$protection = $this->createMock(AccountProtection::class);
		$protection->method('protectedUntil')->willReturnCallback(fn (): ?int => $this->protectedUntil);
		$coverage = $this->createMock(ConfirmationCoverage::class);
		$coverage->method('hasSecondFactor')->willReturnCallback(fn (): bool => $this->secondFactor);
		$loader = $this->createMock(ProviderLoader::class);
		$loader->method('getProviders')->willReturnCallback(function (): array {
			if ($this->providersFail) {
				throw new \Exception('Could not load two-factor auth provider');
			}
			return $this->providers;
		});
		$settings = $this->createMock(Settings::class);
		$settings->method('getInt')->willReturn(90);
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatTime')->willReturnCallback(static fn (int $ts): string => 'time:' . $ts);
		$formatter->method('formatDateTime')->willReturnCallback(static fn (int $ts): string => 'date:' . $ts);
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->willReturnCallback(static fn (string $route, array $parameters): string => $parameters['section']);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		/** @var LoggerInterface&MockObject $logger */
		$logger = $this->createMock(LoggerInterface::class);

		return new PersonalOverview(
			$this->createMock(FailedLoginStats::class),
			$mapper,
			$questions,
			$flag,
			$protection,
			$coverage,
			$loader,
			$this->createMock(UserMessages::class),
			$settings,
			$formatter,
			$urls,
			$time,
			$logger,
		);
	}
}
