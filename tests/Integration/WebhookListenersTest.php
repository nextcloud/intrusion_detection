<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\WebhookListeners\BackgroundJobs\WebhookCall;
use OCA\WebhookListeners\Db\AuthMethod;
use OCA\WebhookListeners\Db\WebhookListenerMapper;
use OCA\WebhookListeners\Listener\WebhooksEventListener;
use OCP\App\IAppManager;
use OCP\BackgroundJob\IJobList;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept section 4, verify item 7: webhook_listeners accepts any event
 * class that implements IWebhookCompatibleEvent, so the app's events can be
 * forwarded without a change there.
 */
#[Group('DB')]
class WebhookListenersTest extends IntegrationTestCase {
	/** @var list<int> */
	private array $webhooks = [];

	protected function setUp(): void {
		parent::setUp();
		$apps = Server::get(IAppManager::class);
		if (!$apps->isEnabledForAnyone('webhook_listeners')) {
			$this->markTestSkipped('webhook_listeners is not enabled');
		}
		$apps->loadApp('webhook_listeners');
	}

	protected function tearDown(): void {
		$mapper = Server::get(WebhookListenerMapper::class);
		foreach ($this->webhooks as $id) {
			$mapper->deleteById($id);
		}
		Server::get(IJobList::class)->remove(WebhookCall::class);
		parent::tearDown();
	}

	public function testAWebhookCanBeRegisteredForEveryEvent(): void {
		$mapper = Server::get(WebhookListenerMapper::class);
		foreach ([DetectionCreatedEvent::class, BanCreatedEvent::class, BanLiftedEvent::class] as $class) {
			$webhook = $mapper->addWebhookListener(null, 'admin', 'POST', 'https://siem.example.com/hook', $class, null, null, null, AuthMethod::None, null);
			$this->webhooks[] = $webhook->getId();
			$this->assertSame($class, $webhook->getEvent());
		}
		$this->assertContains(DetectionCreatedEvent::class, $mapper->getAllConfiguredEvents());
	}

	public function testADetectionIsQueuedForTheWebhookWithItsPayload(): void {
		$mapper = Server::get(WebhookListenerMapper::class);
		$webhook = $mapper->addWebhookListener(null, 'admin', 'POST', 'https://siem.example.com/hook', DetectionCreatedEvent::class, ['event.severity' => 'high'], null, null, AuthMethod::None, null);
		$this->webhooks[] = $webhook->getId();

		$this->settingsEditor()->setGlobal(GlobalSettings::EVENTS_INCLUDE_IP, true);
		$listener = Server::get(WebhooksEventListener::class);
		$listener->handle(new DetectionCreatedEvent($this->detection('high')));
		$listener->handle(new DetectionCreatedEvent($this->detection('low')));

		$calls = [];
		foreach (Server::get(IJobList::class)->getJobsIterator(WebhookCall::class, null, 0) as $job) {
			$argument = $job->getArgument();
			if (is_array($argument) && ($argument[1] ?? null) === $webhook->getId()) {
				$calls[] = $argument[0];
			}
		}
		$this->assertCount(1, $calls, 'the filter on the payload works');
		$event = $calls[0]['event'];
		$this->assertSame(DetectionCreatedEvent::class, $event['class']);
		$this->assertSame('detection', $event['type']);
		$this->assertSame(CredentialStuffing::ID, $event['checkId']);
		$this->assertSame('203.0.113.7', $event['ip']);
	}

	private function detection(string $severity): Detection {
		$detection = new Detection();
		$detection->setId(7);
		$detection->setCheckId(CredentialStuffing::ID);
		$detection->setSeverity($severity);
		$detection->setEnforced(true);
		$detection->setIp('203.0.113.7');
		$detection->setActionList([['type' => 'ban', 'enforced' => true]]);
		$detection->setCreatedAt(time());
		$detection->setLastSeenAt(time());
		$detection->setHits(1);
		return $detection;
	}
}
