<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response\Handlers;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCP\IL10N;
use OCP\L10N\IFactory;
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
		$handler = new BanHandler($this->createMock(BanService::class), $this->createMock(ContainerInterface::class));
		$action = ['type' => 'ban', 'enforced' => true, 'ref' => [
			'bans' => [array_merge(['id' => 1, 'reference' => 'BAAA-AAAB', 'cidr' => '198.51.100.7/32', 'until' => 1], $ban)],
			'counts' => ['banned' => 1, 'already' => 0, 'skipped' => 0],
		]];
		$this->assertSame(
			['Blocked 198.51.100.7/32 until tomorrow (reference BAAA-AAAB, ' . $why . ').'],
			$handler->describeAction($action, $this->l, $this->dates),
		);
	}
}
