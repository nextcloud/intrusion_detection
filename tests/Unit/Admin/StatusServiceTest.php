<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\IStatusContributor;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class StatusServiceTest extends TestCase {
	private Settings&MockObject $settings;
	private LearningService&MockObject $learning;
	private GuardTimer&MockObject $timer;
	private ContainerInterface&MockObject $container;
	private LoggerInterface&MockObject $logger;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(Settings::class);
		$this->settings->method('isEnabled')->willReturn(true);
		$this->learning = $this->createMock(LearningService::class);
		$this->timer = $this->createMock(GuardTimer::class);
		$this->container = $this->createMock(ContainerInterface::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	/**
	 * @param class-string<StatusService> $class
	 */
	private function service(string $class = StatusService::class): StatusService {
		$registry = $this->createMock(CheckRegistry::class);
		$registry->method('configurable')->willReturn([]);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);
		return new $class(
			$this->settings,
			$registry,
			new CheckNames($registry),
			$this->learning,
			$this->createMock(Prerequisites::class),
			$this->createMock(BanMapper::class),
			$this->createMock(DetectionMapper::class),
			$this->createMock(StatsMapper::class),
			$this->timer,
			$time,
			$this->container,
			$this->logger,
		);
	}

	public function testASlowAddressCheckIsAProblem(): void {
		$this->timer->method('summary')->willReturn(['samples' => 40, 'averageMicroseconds' => 1500.0, 'maxMicroseconds' => 9000]);
		$status = $this->service()->status($this->l);
		$this->assertSame(['samples' => 40, 'averageMicroseconds' => 1500.0, 'maxMicroseconds' => 9000], $status['cost']);
		$this->assertSame(['slow_guards'], array_column($status['problems'], 'id'));
	}

	public function testAFastAddressCheckIsNoProblem(): void {
		$this->timer->method('summary')->willReturn(['samples' => 40, 'averageMicroseconds' => 31.04, 'maxMicroseconds' => 90]);
		$status = $this->service()->status($this->l);
		$this->assertSame(31.0, $status['cost']['averageMicroseconds'] ?? null);
		$this->assertSame([], $status['problems']);
	}

	public function testLearningState(): void {
		$this->learning->method('isActive')->willReturn(true);
		$this->learning->method('until')->willReturn(1_790_300_000);
		$this->learning->method('daysLeft')->willReturn(4);
		$service = $this->service();
		$this->assertSame('learning', $service->state());
		$this->assertSame(['active' => true, 'until' => 1_790_300_000, 'daysLeft' => 4, 'minDays' => 1, 'maxDays' => 30], $service->learning());
	}

	public function testContributorsAddDataAndProblemsAndAreIsolatedFromFailures(): void {
		$good = new class implements IStatusContributor {
			public function key(): string {
				return 'lockdown';
			}

			public function data(IL10N $l): ?array {
				return ['until' => 123];
			}

			public function problems(IL10N $l): array {
				return [['id' => 'proxy', 'level' => 'warning', 'title' => 'Proxy', 'text' => 'Configure trusted proxies.', 'url' => null, 'urlLabel' => null]];
			}
		};
		$this->container->method('get')->willReturnCallback(fn (string $class): object => match ($class) {
			'Good' => $good,
			default => throw new \RuntimeException('broken'),
		});
		$this->logger->expects($this->once())->method('error');

		$status = $this->service(ContributingStatusService::class)->status($this->l);

		$this->assertSame(['lockdown' => ['until' => 123]], $status['extensions']);
		$this->assertSame(['proxy'], array_column($status['problems'], 'id'));
	}
}

/**
 * A status service with one working and one broken contributor.
 */
class ContributingStatusService extends StatusService {
	public const CONTRIBUTORS = ['Broken', 'Good'];
}
