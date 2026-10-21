<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Dashboard;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\ConfirmationOverview;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Dashboard\IntrusionWidget;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Dashboard\Model\WidgetButton;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class IntrusionWidgetTest extends TestCase {
	private StatusService&MockObject $status;
	private ConfirmationOverview&MockObject $confirmation;
	private DetectionMapper&MockObject $detections;
	private IUserSession&MockObject $session;
	private IGroupManager&MockObject $groups;
	private IntrusionWidget $widget;

	protected function setUp(): void {
		parent::setUp();
		$this->status = $this->createMock(StatusService::class);
		$this->confirmation = $this->createMock(ConfirmationOverview::class);
		$this->detections = $this->createMock(DetectionMapper::class);
		$this->session = $this->createMock(IUserSession::class);
		$this->groups = $this->createMock(IGroupManager::class);
		$this->groups->method('isAdmin')->willReturnCallback(static fn (string $uid): bool => $uid === 'admin');
		$names = $this->createMock(CheckNames::class);
		$names->method('name')->willReturnCallback(static fn (string $id): string => 'Name of ' . $id);
		$names->method('category')->willReturn(Category::Internal);
		$dates = $this->createMock(DateFormatter::class);
		$dates->method('dateTime')->willReturn('10/20/26, 10:00 AM');
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRouteAbsolute')->willReturn('https://cloud.example/settings/admin/intrusion_detection');
		$urls->method('imagePath')->willReturnCallback(static fn (string $app, string $image): string => '/apps/' . $app . '/img/' . $image);
		$urls->method('getAbsoluteURL')->willReturnArgument(0);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);

		$this->widget = new IntrusionWidget(
			$this->status,
			$this->confirmation,
			$this->detections,
			$names,
			$dates,
			$this->session,
			$this->groups,
			$urls,
			$time,
			Server::get(IFactory::class)->get('intrusion_detection', 'en'),
		);
	}

	private function loggedInAs(?string $uid): void {
		$user = null;
		if ($uid !== null) {
			$user = $this->createMock(IUser::class);
			$user->method('getUID')->willReturn($uid);
		}
		$this->session->method('getUser')->willReturn($user);
	}

	public function testOnlyAdministratorsGetTheWidget(): void {
		$this->loggedInAs('admin');
		$this->assertTrue($this->widget->isEnabled());
	}

	public function testOtherUsersDoNotGetTheWidget(): void {
		$this->loggedInAs('bob');
		$this->assertFalse($this->widget->isEnabled());
	}

	public function testNobodyLoggedInGetsNoWidget(): void {
		$this->loggedInAs(null);
		$this->assertFalse($this->widget->isEnabled());
	}

	public function testItemsAreNeverGivenToOtherUsers(): void {
		$this->status->expects($this->never())->method('status');
		$this->detections->expects($this->never())->method('findList');
		$this->assertSame([], $this->widget->getItemsV2('bob')->getItems());
	}

	public function testStatusLineAndSeriousDetections(): void {
		$this->status->method('status')->willReturn(self::statusData('protecting', blocked: 41, detections: 12));
		$filter = null;
		$this->detections->method('findList')->willReturnCallback(function (DetectionFilter $f) use (&$filter): array {
			$filter = $f;
			return [self::detection(7, 'account_takeover', true), self::detection(8, 'decoy_credential', false)];
		});

		$items = $this->widget->getItemsV2('admin')->getItems();

		$this->assertSame(['high', 'critical'], $filter?->severities);
		$this->assertSame(5, $filter?->limit);
		$this->assertCount(3, $items);
		$this->assertSame('Protecting', $items[0]->getTitle());
		$this->assertSame('41 addresses blocked in 24 hours · 12 detections', $items[0]->getSubtitle());
		$this->assertSame('Name of account_takeover', $items[1]->getTitle());
		$this->assertSame('198.51.100.7 · alice · 10/20/26, 10:00 AM', $items[1]->getSubtitle());
		$this->assertStringEndsWith('#detection-7', $items[1]->getLink());
		$this->assertSame('Name of decoy_credential (observed)', $items[2]->getTitle());
	}

	public function testLoginsWaitingForThisAdministratorComeFirst(): void {
		$this->status->method('status')->willReturn(self::statusData('protecting', blocked: 0, detections: 0));
		$this->confirmation->expects($this->once())->method('pendingLogins')->with('admin')->willReturn([
			['id' => 3, 'uid' => 'alice', 'displayName' => 'Alice Liddell', 'ip' => '203.0.113.9', 'createdAt' => 1_789_999_000, 'expiresAt' => 1_790_001_000, 'canDecide' => true],
			['id' => 4, 'uid' => 'admin', 'displayName' => 'Admin', 'ip' => null, 'createdAt' => 1_789_999_500, 'expiresAt' => 1_790_001_500, 'canDecide' => false],
		]);
		$filter = null;
		$this->detections->method('findList')->willReturnCallback(function (DetectionFilter $f) use (&$filter): array {
			$filter = $f;
			return [];
		});

		$items = $this->widget->getItemsV2('admin')->getItems();

		$this->assertSame('Alice Liddell waits for your approval', $items[0]->getTitle());
		$this->assertSame('Login from 203.0.113.9', $items[0]->getSubtitle());
		$this->assertStringEndsWith('#overview-attention', $items[0]->getLink());
		$this->assertStringEndsWith('widget-approval.svg', $items[0]->getIconUrl());
		$this->assertSame('Protecting', $items[1]->getTitle());
		$this->assertCount(2, $items, 'Their own login is not offered to an administrator');
		$this->assertSame(5, $filter?->limit);
	}

	public function testItemIconsReadInBothThemes(): void {
		$this->status->method('status')->willReturn(self::statusData('protecting', blocked: 1, detections: 1));
		$this->detections->method('findList')->willReturn([self::detection(7, 'account_takeover', true)]);

		$items = $this->widget->getItemsV2('admin')->getItems();

		$this->assertSame('/apps/intrusion_detection/img/widget-status.svg', $items[0]->getIconUrl());
		$this->assertSame('/apps/intrusion_detection/img/widget-detection.svg', $items[1]->getIconUrl());
		foreach (['widget-status.svg', 'widget-detection.svg'] as $image) {
			$svg = (string)file_get_contents(__DIR__ . '/../../../img/' . $image);
			$this->assertStringContainsString('fill="#0082c9"', $svg, 'A fixed colour that reads on light and dark backgrounds');
			$this->assertStringNotContainsString('#000', $svg);
		}
	}

	public function testWithASinceIdOnlyNewerDetectionsAreReturned(): void {
		$this->status->expects($this->never())->method('status');
		$filter = null;
		$this->detections->method('findList')->willReturnCallback(function (DetectionFilter $f) use (&$filter): array {
			$filter = $f;
			return [self::detection(9, 'account_takeover', true)];
		});

		$items = $this->widget->getItemsV2('admin', '8', 7);

		$this->assertSame(8, $filter?->afterId);
		$this->assertSame(IntrusionWidget::MAX_DETECTIONS, $filter?->limit);
		$this->assertSame(['9'], array_map(static fn ($item): string => $item->getSinceId(), $items->getItems()));
		$this->assertSame('', $items->getEmptyContentMessage());
	}

	public function testLearningAndOff(): void {
		$this->status->method('status')->willReturnOnConsecutiveCalls(self::statusData('learning', daysLeft: 4, wouldHave: 3), self::statusData('off'));
		$this->detections->method('findList')->willReturn([]);

		$learning = $this->widget->getItemsV2('admin');
		$this->assertSame('Learning mode, 4 days left', $learning->getItems()[0]->getTitle());
		$this->assertStringStartsWith('Would have blocked 3 addresses', $learning->getItems()[0]->getSubtitle());
		$this->assertSame('No serious detections in the last 30 days.', $learning->getHalfEmptyContentMessage());

		$this->assertSame('Off: no checks run', $this->widget->getItemsV2('admin')->getItems()[0]->getTitle());
	}

	public function testButtonOpensTheAdminPage(): void {
		$buttons = $this->widget->getWidgetButtons('admin');
		$this->assertCount(1, $buttons);
		$this->assertSame(WidgetButton::TYPE_MORE, $buttons[0]->getType());
		$this->assertSame('Open intrusion detection', $buttons[0]->getText());
		$this->assertSame('https://cloud.example/settings/admin/intrusion_detection', $buttons[0]->getLink());
		$this->assertSame(300, $this->widget->getReloadInterval());
		$this->assertSame('intrusion_detection', $this->widget->getId());
	}

	/**
	 * @return array<string, mixed>
	 */
	private static function statusData(string $state, int $blocked = 0, int $detections = 0, int $daysLeft = 0, int $wouldHave = 0): array {
		return [
			'state' => $state,
			'learning' => ['active' => $state === 'learning', 'until' => 0, 'daysLeft' => $daysLeft, 'minDays' => 1, 'maxDays' => 30],
			'checks' => ['protect' => 0, 'observe' => 0, 'off' => 0],
			'last24h' => ['detections' => $detections, 'enforced' => 0, 'observed' => 0, 'blockedAddresses' => $blocked, 'wouldHaveBlocked' => $wouldHave, 'accounts' => 0, 'categories' => []],
			'activeBans' => 0,
			'prerequisites' => ['memoryCache' => 'none', 'mail' => false],
			'cost' => null,
			'costSampleRate' => 1000,
			'problems' => [],
			'extensions' => [],
		];
	}

	private static function detection(int $id, string $checkId, bool $enforced): Detection {
		$detection = new Detection();
		$detection->setId($id);
		$detection->setCheckId($checkId);
		$detection->setEnforced($enforced);
		$detection->setIp('198.51.100.7');
		$detection->setUid('alice');
		$detection->setLastSeenAt(1_790_000_000);
		return $detection;
	}
}
