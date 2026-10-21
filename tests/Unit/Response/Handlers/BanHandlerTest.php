<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response\Handlers;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Test\TestCase;

class BanHandlerTest extends TestCase {
	private IL10N $l;
	private DateFormatter $dates;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$dates = $this->createMock(DateFormatter::class);
		$dates->method('dateTime')->willReturn('tomorrow');
		$this->dates = $dates;
	}

	/**
	 * @return array<string, array{array<string, mixed>, string}>
	 */
	public static function bans(): array {
		return [
			'first' => [['level' => 1], 'first block'],
			'second' => [['level' => 2], 'second block within the history window'],
			'escalated' => [['level' => 3], 'blocked again within the history window'],
			'set by the check' => [['level' => 3, 'forced' => true], 'this check blocks for this long right away'],
			'stored before the flag existed' => [[], 'first block'],
		];
	}

	#[DataProvider('bans')]
	public function testTheSentenceSaysWhyTheBlockLastsThisLong(array $ban, string $why): void {
		$handler = $this->handler($this->banService());
		$action = ['type' => 'ban', 'enforced' => true, 'ref' => [
			'bans' => [array_merge(['id' => 1, 'reference' => 'BAAA-AAAB', 'cidr' => '198.51.100.7/32', 'until' => 1], $ban)],
			'counts' => ['banned' => 1, 'already' => 0, 'skipped' => 0],
		]];
		$this->assertSame(
			['Blocked 198.51.100.7/32 until tomorrow (reference BAAA-AAAB, ' . $why . ').'],
			$handler->describeAction($action, $this->l, $this->dates),
		);
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function lureChecks(): array {
		return [
			'a trap URL' => [TrapUrl::ID],
			'an injection probe' => [InjectionProbe::ID],
			'an unknown share link' => [ShareBruteforce::ID],
		];
	}

	#[DataProvider('lureChecks')]
	public function testALureNeverBlocksTheAddressOfTheRequest(string $checkId): void {
		$bans = $this->banService();
		$bans->expects($this->never())->method('banMany');
		$outcome = $this->handler($bans)->apply($this->context($this->lure($checkId)));
		$this->assertFalse($outcome->enforced);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
		$this->assertSame(1, $outcome->ref['counts']['lure']);
		$sentences = $this->handler($bans)->describeAction(['type' => 'ban', 'enforced' => false, 'note' => $outcome->note, 'ref' => $outcome->ref], $this->l, $this->dates);
		$this->assertStringContainsString('a browser made it for another website or an email', implode(' ', $sentences));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function checksWithoutLures(): array {
		return [
			'password spraying' => ['password_spraying'],
			'credential stuffing' => ['credential_stuffing'],
			'an account under attack' => ['account_under_attack'],
			'a decoy' => ['decoy_credential'],
		];
	}

	#[DataProvider('checksWithoutLures')]
	public function testOtherChecksBlockALure(string $checkId): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$bans = $this->banService();
		$bans->expects($this->once())->method('banMany')->with([$source])->willReturn([$source->ipKey => new BanResult(BanResult::BANNED, $this->ban())]);
		$outcome = $this->handler($bans)->apply($this->context($this->lure($checkId)));
		$this->assertTrue($outcome->enforced);
		$this->assertSame(0, $outcome->ref['counts']['lure']);
	}

	public function testARequestThatIsNoLureIsBlocked(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$bans = $this->banService();
		$bans->expects($this->once())->method('banMany')->with([$source])->willReturn([$source->ipKey => new BanResult(BanResult::BANNED, $this->ban())]);
		$outcome = $this->handler($bans)->apply($this->context());
		$this->assertTrue($outcome->enforced);
		$this->assertSame(0, $outcome->ref['counts']['lure']);
	}

	public function testALureOnlySparesTheAddressOfTheRequest(): void {
		$other = SourceKey::fromIp('203.0.113.9');
		$draft = $this->lure(ShareBruteforce::ID);
		$draft->addBanTarget($other);
		$bans = $this->banService();
		$bans->expects($this->once())->method('banMany')->with([$other])->willReturn([$other->ipKey => new BanResult(BanResult::BANNED, $this->ban())]);
		$outcome = $this->handler($bans)->apply($this->context($draft));
		$this->assertTrue($outcome->enforced);
		$this->assertSame(['banned' => 1, 'already' => 0, 'skipped' => 0, 'lure' => 1, 'trusted' => 0, 'proxy' => 0], $outcome->ref['counts']);
	}

	public function testTheAddressOfTrustedLoginsIsHeldBackAndSaysWhy(): void {
		$bans = $this->banService();
		$bans->method('banMany')->willReturnCallback(static fn (array $targets): array => array_fill_keys(array_map(static fn (SourceKey $t): string => $t->ipKey, $targets), new BanResult(BanResult::SKIPPED_TRUSTED)));
		$outcome = $this->handler($bans)->apply($this->context());
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
		$this->assertSame(1, $outcome->ref['counts']['trusted']);
		$sentences = $this->handler($bans)->describeAction(['type' => 'ban', 'enforced' => false, 'note' => $outcome->note, 'ref' => $outcome->ref], $this->l, $this->dates);
		$this->assertSame(['1 address was not blocked: within the last 7 days an administrator logged in from it, or the account the detection is about confirmed a login from it.'], $sentences);
	}

	public function testAnUnconfiguredProxyIsReportedAsASharedAddress(): void {
		$bans = $this->banService();
		$bans->method('banMany')->willReturnCallback(static fn (array $targets): array => array_fill_keys(array_map(static fn (SourceKey $t): string => $t->ipKey, $targets), new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: 4)));
		$bans->method('firstReport')->willReturn(true);
		$engine = $this->createMock(ResponseEngine::class);
		$engine->expects($this->once())->method('handle')->with($this->callback(
			static fn (DetectionDraft $draft): bool => $draft->checkId === SharedAddress::ID && $draft->facts === ['users' => 4, 'wantedBy' => 'trap_url', 'proxy' => true],
		));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->with(ResponseEngine::class)->willReturn($engine);
		$handler = new BanHandler($bans, $container);
		$outcome = $handler->apply($this->context());
		$this->assertSame(1, $outcome->ref['counts']['proxy']);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
	}

	public function testAHeldBackAddressIsReportedOncePerMinute(): void {
		$bans = $this->banService();
		$bans->method('banMany')->willReturnCallback(static fn (array $targets): array => array_fill_keys(array_map(static fn (SourceKey $t): string => $t->ipKey, $targets), new BanResult(BanResult::SKIPPED_SHARED, sharedUsers: 6)));
		$bans->method('firstReport')->willReturn(false);
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$outcome = (new BanHandler($bans, $container))->apply($this->context());
		$this->assertSame(1, $outcome->ref['counts']['skipped']);
	}

	public function testASparedSourceIsNotBlockedButANetworkIs(): void {
		$draft = new DetectionDraft(checkId: 'credential_stuffing', source: SourceKey::fromIp('198.51.100.7'));
		$draft->spareSource();
		$draft->addNetworkBanTarget(SourceKey::fromIp('198.51.100.9'));
		$net = $this->ban();
		$net->setCidr('198.51.100.0/24');
		$bans = $this->banService();
		$bans->expects($this->never())->method('banMany');
		$bans->expects($this->once())->method('banNetwork')->with(SourceKey::fromIp('198.51.100.9'), 'credential_stuffing', 5)->willReturn(new BanResult(BanResult::BANNED, $net));
		$outcome = $this->handler($bans)->apply($this->context($draft));
		$this->assertTrue($outcome->enforced);
		$this->assertSame('198.51.100.0/24', $outcome->ref['bans'][0]['cidr']);
		$this->assertSame(1, $outcome->ref['counts']['banned']);
	}

	public function testTheBanKnowsTheAccountOfTheDetection(): void {
		$bans = $this->banService();
		$bans->expects($this->once())->method('banMany')->with([SourceKey::fromIp('198.51.100.7')], 'account_under_attack', 5, null, 'alice')->willReturn(['198.51.100.7' => new BanResult(BanResult::BANNED, $this->ban())]);
		$this->handler($bans)->apply($this->context(new DetectionDraft(checkId: 'account_under_attack', source: SourceKey::fromIp('198.51.100.7'), uid: 'alice')));
	}

	/**
	 * A ban service whose batches just run their work.
	 */
	private function banService(): BanService&MockObject {
		$bans = $this->createMock(BanService::class);
		$bans->method('batch')->willReturnCallback(static fn (\Closure $work): mixed => $work());
		return $bans;
	}

	private function handler(BanService $bans): BanHandler {
		return new BanHandler($bans, $this->createMock(ContainerInterface::class));
	}

	private function lure(string $checkId): DetectionDraft {
		return new DetectionDraft(checkId: $checkId, source: SourceKey::fromIp('198.51.100.7'), lure: true);
	}

	private function context(?DetectionDraft $draft = null): ResponseContext {
		$detection = new Detection();
		$detection->setId(5);
		return new ResponseContext(
			$draft ?? new DetectionDraft(checkId: 'trap_url', source: SourceKey::fromIp('198.51.100.7')),
			$detection,
			(new TrapUrl($this->dates))->definition(),
			true,
		);
	}

	private function ban(): Ban {
		$ban = new Ban();
		$ban->setId(9);
		$ban->setReference('BAAAAAAB');
		$ban->setCidr('198.51.100.7/32');
		$ban->setLevel(1);
		$ban->setExpiresAt(time() + 3600);
		return $ban;
	}
}
