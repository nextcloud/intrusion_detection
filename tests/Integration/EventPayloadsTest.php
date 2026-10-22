<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Event\EventExamples;
use OCA\IntrusionDetection\Event\EventPayloads;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Response\BanService;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\EventDispatcher\IWebhookCompatibleEvent;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The typed events' webhook payloads (concept section 11.11).
 */
#[Group('DB')]
class EventPayloadsTest extends IntegrationTestCase {
	private const SECRETS = ['Secret-Password-5f5f', 'SecretShareTokenQ7', 'Qx7Kp-Zt3Wm-Rb8Nc-Jd2Hf-Ls9Gy', 'admin-note-secret', 'recipient-uid-secret'];

	protected function setUp(): void {
		parent::setUp();
	}

	public function testTheEventsAreWebhookCompatible(): void {
		foreach ([DetectionCreatedEvent::class, BanCreatedEvent::class, BanLiftedEvent::class] as $class) {
			$this->assertTrue(is_a($class, IWebhookCompatibleEvent::class, true), $class);
		}
	}

	public function testADetectionPayloadHasExactlyTheDocumentedKeys(): void {
		$payload = (new DetectionCreatedEvent($this->detection()))->getWebhookSerializable();
		$this->assertSame(['type', 'detectionId', 'checkId', 'severity', 'enforced', 'ip', 'uid', 'actions', 'time', 'link'], array_keys($payload));
		$this->assertSame('detection', $payload['type']);
		$this->assertSame(42, $payload['detectionId']);
		$this->assertSame(CredentialStuffing::ID, $payload['checkId']);
		$this->assertSame('high', $payload['severity']);
		$this->assertTrue($payload['enforced']);
		$this->assertSame('198.51.100.7', $payload['ip']);
		$this->assertSame('alice', $payload['uid']);
		$this->assertSame(1_800_000_000, $payload['time']);
		$this->assertSame(Server::get(AdminLinks::class)->detection(42), $payload['link']);
		$this->assertSame([
			['type' => 'ban', 'enforced' => true, 'bans' => [['reference' => 'K7Q2-MPXA', 'expiresAt' => 1_800_014_400]]],
			['type' => 'flag_source', 'enforced' => true],
			['type' => 'notify_admin', 'enforced' => true],
			['type' => 'step_up', 'enforced' => false],
		], $payload['actions']);
	}

	public function testBanPayloadsHaveExactlyTheDocumentedKeys(): void {
		$ban = $this->ban();
		$created = (new BanCreatedEvent($ban, true))->getWebhookSerializable();
		$this->assertSame(['type', 'reference', 'scope', 'cidr', 'checkId', 'detectionId', 'link', 'raised', 'level', 'createdBy', 'time', 'expiresAt'], array_keys($created));
		$this->assertSame(['ban_created', 'K7Q2-MPXA', 'ip', '198.51.100.7/32', CredentialStuffing::ID, 42], array_slice(array_values($created), 0, 6));
		$this->assertTrue($created['raised']);
		$this->assertSame(2, $created['level']);
		$this->assertNull($created['createdBy']);
		$this->assertSame(Server::get(AdminLinks::class)->detection(42), $created['link']);

		$ban->setLiftedAt(1_800_000_600);
		$ban->setLiftedBy('admin');
		$lifted = (new BanLiftedEvent($ban))->getWebhookSerializable();
		$this->assertSame(['type', 'reference', 'scope', 'cidr', 'checkId', 'detectionId', 'link', 'liftedBy', 'time', 'expiresAt'], array_keys($lifted));
		$this->assertSame('ban_lifted', $lifted['type']);
		$this->assertSame('admin', $lifted['liftedBy']);
		$this->assertSame(1_800_000_600, $lifted['time']);

		$ban->setDetectionId(null);
		$ban->setCreatedBy('admin');
		$manual = (new BanCreatedEvent($ban))->getWebhookSerializable();
		$this->assertSame(Server::get(AdminLinks::class)->adminPage() . '#blocks', $manual['link']);
		$this->assertSame('admin', $manual['createdBy']);
	}

	public function testTheAddressIsLeftOutWhenConfigured(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::EVENTS_INCLUDE_IP, false);
		$detection = (new DetectionCreatedEvent($this->detection()))->getWebhookSerializable();
		$created = (new BanCreatedEvent($this->ban()))->getWebhookSerializable();
		$lifted = (new BanLiftedEvent($this->ban()))->getWebhookSerializable();
		$this->assertArrayNotHasKey('ip', $detection);
		$this->assertArrayNotHasKey('cidr', $created);
		$this->assertArrayNotHasKey('cidr', $lifted);
		foreach ([$detection, $created, $lifted] as $payload) {
			$this->assertStringNotContainsString('198.51.100.7', json_encode($payload, JSON_THROW_ON_ERROR));
		}
	}

	public function testPayloadsCarryNoSecretsNotesOrExplanations(): void {
		$ban = $this->ban();
		$ban->setNote('admin-note-secret');
		$ban->setLiftNote('admin-note-secret');
		$json = json_encode([
			(new DetectionCreatedEvent($this->detection()))->getWebhookSerializable(),
			(new BanCreatedEvent($ban))->getWebhookSerializable(),
			(new BanLiftedEvent($ban))->getWebhookSerializable(),
		], JSON_THROW_ON_ERROR);
		foreach (self::SECRETS as $secret) {
			$this->assertStringNotContainsString($secret, $json);
		}
		$this->assertStringNotContainsString('explanation', $json);
		$this->assertStringNotContainsString('recipients', $json);
	}

	public function testManyBansStayASmallPayload(): void {
		$bans = [];
		for ($i = 0; $i < 60; $i++) {
			$bans[] = ['id' => $i, 'reference' => sprintf('AAAA-%04d', $i), 'cidr' => '198.51.100.' . $i . '/32', 'level' => 1, 'until' => 1_800_014_400];
		}
		$detection = $this->detection();
		$detection->setActionList([['type' => 'ban', 'enforced' => true, 'ref' => ['bans' => $bans]]]);
		$payload = (new DetectionCreatedEvent($detection))->getWebhookSerializable();
		$this->assertCount(EventPayloads::MAX_BANS, $payload['actions'][0]['bans']);
		$this->assertLessThan(2000, strlen(json_encode($payload, JSON_THROW_ON_ERROR)));
	}

	public function testABrokenPayloadNeverBreaksTheDispatch(): void {
		$links = $this->createMock(AdminLinks::class);
		$links->method('detection')->willThrowException(new \RuntimeException('no router'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$payloads = new EventPayloads($this->appSettings(), $links, $logger);
		$this->assertSame(['type' => 'detection'], (new DetectionCreatedEvent($this->detection(), $payloads))->getWebhookSerializable());
	}

	public function testBlockingDispatchesAnEventWithThePayload(): void {
		$received = [];
		$listener = static function (BanCreatedEvent|BanLiftedEvent $event) use (&$received): void {
			$received[] = $event->getWebhookSerializable();
		};
		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->addListener(BanCreatedEvent::class, $listener);
		$dispatcher->addListener(BanLiftedEvent::class, $listener);
		try {
			$bans = Server::get(BanService::class);
			$ban = $bans->banManually('192.0.2.44', 1, 'admin', 'note');
			$bans->lift($ban, 'admin', 'lifted');
		} finally {
			$dispatcher->removeListener(BanCreatedEvent::class, $listener);
			$dispatcher->removeListener(BanLiftedEvent::class, $listener);
		}
		$this->assertSame(['ban_created', 'ban_lifted'], array_column($received, 'type'));
		$this->assertSame('192.0.2.44/32', $received[0]['cidr']);
		$this->assertSame('admin', $received[1]['liftedBy']);
	}

	public function testTheExamplesAreTheRealPayloads(): void {
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$examples = Server::get(EventExamples::class)->all($l);
		$this->assertSame([DetectionCreatedEvent::class, BanCreatedEvent::class, BanLiftedEvent::class], array_column($examples, 'class'));
		foreach ($examples as $example) {
			$this->assertSame(['event', 'user', 'time'], array_keys($example['example']));
			$this->assertSame($example['class'], $example['example']['event']['class']);
			$this->assertNotSame('', $example['name']);
			$this->assertNotSame('', $example['description']);
		}
		$detection = $examples[0]['example']['event'];
		$this->assertSame(['type', 'detectionId', 'checkId', 'severity', 'enforced', 'ip', 'uid', 'actions', 'time', 'link', 'class'], array_keys($detection));
		$this->assertSame(EventExamples::EXAMPLE_IP, $detection['ip']);
		$this->assertSame('K7Q2-MPXA', $detection['actions'][0]['bans'][0]['reference']);

		$this->settingsEditor()->setGlobal(GlobalSettings::EVENTS_INCLUDE_IP, false);
		$examples = Server::get(EventExamples::class)->all($l);
		$this->assertStringNotContainsString(EventExamples::EXAMPLE_IP, json_encode($examples, JSON_THROW_ON_ERROR));
	}

	private function detection(): Detection {
		$detection = new Detection();
		$detection->setId(42);
		$detection->setCheckId(CredentialStuffing::ID);
		$detection->setSeverity('high');
		$detection->setEnforced(true);
		$detection->setIp('198.51.100.7');
		$detection->setNetKey('198.51.100.0/24');
		$detection->setUid('alice');
		$detection->setExplanationData(['facts' => ['password' => self::SECRETS[0], 'token' => self::SECRETS[1]], 'userAgent' => self::SECRETS[2]]);
		$detection->setActionList([
			['type' => 'ban', 'enforced' => true, 'ref' => ['bans' => [['id' => 7, 'reference' => 'K7Q2-MPXA', 'cidr' => '198.51.100.7/32', 'level' => 1, 'until' => 1_800_014_400]], 'counts' => ['banned' => 1]]],
			['type' => 'flag_source', 'enforced' => true, 'ref' => ['until' => 1_800_086_400]],
			['type' => 'notify_admin', 'enforced' => true, 'ref' => ['recipients' => ['recipient-uid-secret'], 'email' => 'sent']],
			['type' => 'step_up', 'enforced' => false, 'note' => 'unavailable'],
		]);
		$detection->setCreatedAt(1_800_000_000);
		$detection->setLastSeenAt(1_800_000_000);
		$detection->setHits(3);
		return $detection;
	}

	private function ban(): Ban {
		$ban = new Ban();
		$ban->setId(7);
		$ban->setReference('K7Q2MPXA');
		$ban->setCidr('198.51.100.7/32');
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setBanKey('198.51.100.7');
		$ban->setLevel(2);
		$ban->setCheckId(CredentialStuffing::ID);
		$ban->setDetectionId(42);
		$ban->setCreatedAt(1_800_000_000);
		$ban->setExpiresAt(1_800_086_400);
		return $ban;
	}
}
