<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response\Handlers;

use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;
use OCP\IRequest;
use OCP\L10N\IFactory;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
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
		$handler = $this->handler($this->createMock(BanService::class));
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
	 * @return array<string, array{array<string, string>}>
	 */
	public static function lures(): array {
		return [
			'another site' => [['Sec-Fetch-Site' => 'cross-site', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document']],
			'an image' => [['Sec-Fetch-Site' => 'same-site', 'Sec-Fetch-Mode' => 'no-cors', 'Sec-Fetch-Dest' => 'image']],
			'a script, header case and spaces' => [['Sec-Fetch-Dest' => ' Script ']],
			'a frame' => [['Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'iframe']],
		];
	}

	#[DataProvider('lures')]
	public function testALureNeverBlocksTheAddressOfTheRequest(array $headers): void {
		$bans = $this->createMock(BanService::class);
		$bans->expects($this->never())->method('ban');
		$outcome = $this->handler($bans, $headers)->apply($this->context());
		$this->assertFalse($outcome->enforced);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
		$this->assertSame(1, $outcome->ref['counts']['lure']);
		$sentences = $this->handler($bans)->describeAction(['type' => 'ban', 'enforced' => false, 'note' => $outcome->note, 'ref' => $outcome->ref], $this->l, $this->dates);
		$this->assertStringContainsString('a browser made it for another website or an email', implode(' ', $sentences));
	}

	/**
	 * @return array<string, array{array<string, string>}>
	 */
	public static function noLures(): array {
		return [
			'a script without fetch metadata' => [[]],
			'the user went there' => [['Sec-Fetch-Site' => 'none', 'Sec-Fetch-Mode' => 'navigate', 'Sec-Fetch-Dest' => 'document']],
			'a script of the same site' => [['Sec-Fetch-Site' => 'same-origin', 'Sec-Fetch-Mode' => 'cors', 'Sec-Fetch-Dest' => 'empty']],
		];
	}

	#[DataProvider('noLures')]
	public function testOtherRequestsBlockAsBefore(array $headers): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$bans = $this->createMock(BanService::class);
		$bans->expects($this->once())->method('ban')->with($source)->willReturn(new BanResult(BanResult::BANNED, $this->ban()));
		$outcome = $this->handler($bans, $headers)->apply($this->context());
		$this->assertTrue($outcome->enforced);
		$this->assertSame(0, $outcome->ref['counts']['lure']);
	}

	public function testALureOnlySparesTheAddressOfTheRequest(): void {
		$other = SourceKey::fromIp('203.0.113.9');
		$draft = new DetectionDraft(checkId: 'password_spraying', source: SourceKey::fromIp('198.51.100.7'));
		$draft->addBanTarget($other);
		$bans = $this->createMock(BanService::class);
		$bans->expects($this->once())->method('ban')->with($other)->willReturn(new BanResult(BanResult::BANNED, $this->ban()));
		$outcome = $this->handler($bans, ['Sec-Fetch-Site' => 'cross-site'])->apply($this->context($draft));
		$this->assertTrue($outcome->enforced);
		$this->assertSame(['banned' => 1, 'already' => 0, 'skipped' => 0, 'lure' => 1, 'trusted' => 0, 'proxy' => 0], $outcome->ref['counts']);
	}

	public function testALureFromAnotherAddressBlocksTheDetectionsSource(): void {
		$bans = $this->createMock(BanService::class);
		$bans->expects($this->once())->method('ban')->willReturn(new BanResult(BanResult::BANNED, $this->ban()));
		$this->assertTrue($this->handler($bans, ['Sec-Fetch-Site' => 'cross-site'], '203.0.113.50')->apply($this->context())->enforced);
	}

	public function testTheAddressOfTrustedLoginsIsHeldBackAndSaysWhy(): void {
		$bans = $this->createMock(BanService::class);
		$bans->method('ban')->willReturn(new BanResult(BanResult::SKIPPED_TRUSTED));
		$outcome = $this->handler($bans)->apply($this->context());
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
		$this->assertSame(1, $outcome->ref['counts']['trusted']);
		$sentences = $this->handler($bans)->describeAction(['type' => 'ban', 'enforced' => false, 'note' => $outcome->note, 'ref' => $outcome->ref], $this->l, $this->dates);
		$this->assertSame(['1 address was not blocked: within the last 7 days someone confirmed a login from it, or an administrator logged in from it.'], $sentences);
	}

	public function testAnUnconfiguredProxyIsReportedAsASharedAddress(): void {
		$bans = $this->createMock(BanService::class);
		$bans->method('ban')->willReturn(new BanResult(BanResult::SKIPPED_PROXY, sharedUsers: 4));
		$engine = $this->createMock(ResponseEngine::class);
		$engine->expects($this->once())->method('handle')->with($this->callback(
			static fn (DetectionDraft $draft): bool => $draft->checkId === SharedAddress::ID && $draft->facts === ['users' => 4, 'wantedBy' => 'trap_url', 'proxy' => true],
		));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->with(ResponseEngine::class)->willReturn($engine);
		$request = $this->createMock(IRequest::class);
		$handler = new BanHandler($bans, $container, $request, new RemoteAddressResolver($request, $this->createMock(IThrottler::class)));
		$outcome = $handler->apply($this->context());
		$this->assertSame(1, $outcome->ref['counts']['proxy']);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);
	}

	/**
	 * @param array<string, string> $headers
	 */
	private function handler(BanService $bans, array $headers = [], string $requestAddress = '198.51.100.7'): BanHandler {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $headers[$name] ?? '');
		$request->method('getRemoteAddress')->willReturn($requestAddress);
		return new BanHandler($bans, $this->createMock(ContainerInterface::class), $request, new RemoteAddressResolver($request, $this->createMock(IThrottler::class)));
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
