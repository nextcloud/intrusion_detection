<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IWebhookCompatibleEvent;
use OCP\IL10N;

/**
 * The typed events with an example of what a webhook receives, for the
 * admin page. The examples come from real event objects, built in memory
 * from made-up records, so they always match the current payload and the
 * current `events_include_ip` setting.
 *
 * @psalm-import-type IntrusionDetectionWebhookEvent from ResponseDefinitions
 */
class EventExamples {
	public const EXAMPLE_IP = '203.0.113.7';
	public const EXAMPLE_REFERENCE = 'K7Q2MPXA';
	public const EXAMPLE_DETECTION = 42;
	public const EXAMPLE_BAN = 7;

	public function __construct(
		private readonly EventPayloads $payloads,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return list<IntrusionDetectionWebhookEvent>
	 */
	public function all(IL10N $l): array {
		$now = $this->timeFactory->getTime();
		$detection = $this->detection($now);
		$ban = $this->ban($now);
		$lifted = $this->ban($now);
		$lifted->setLiftedAt($now + 600);
		$lifted->setLiftedBy('admin');

		return [
			[
				'class' => DetectionCreatedEvent::class,
				'name' => $l->t('A check found something'),
				'description' => $l->t('Sent for every new detection, in Protect and in Observe mode. "enforced" says whether Nextcloud acted, "actions" what it did.'),
				'example' => $this->envelope(new DetectionCreatedEvent($detection, $this->payloads), $now),
			],
			[
				'class' => BanCreatedEvent::class,
				'name' => $l->t('An address was blocked'),
				'description' => $l->t('Sent when an address or network is blocked, and when an existing block is raised to a higher level ("raised").'),
				'example' => $this->envelope(new BanCreatedEvent($ban, false, $this->payloads), $now),
			],
			[
				'class' => BanLiftedEvent::class,
				'name' => $l->t('A block was lifted'),
				'description' => $l->t('Sent when an administrator lifts a block before it ends. Blocks that simply expire send no event.'),
				'example' => $this->envelope(new BanLiftedEvent($lifted, $this->payloads), $now + 600),
			],
		];
	}

	/**
	 * What webhook_listeners sends: the event's payload with its class, the
	 * logged-in user (none for an attacker) and the time.
	 *
	 * @return array<string, mixed>
	 */
	private function envelope(IWebhookCompatibleEvent $event, int $time): array {
		return [
			'event' => $event->getWebhookSerializable() + ['class' => $event::class],
			'user' => null,
			'time' => $time,
		];
	}

	private function detection(int $now): Detection {
		$detection = new Detection();
		$detection->setId(self::EXAMPLE_DETECTION);
		$detection->setCheckId(CredentialStuffing::ID);
		$detection->setSeverity(Severity::Medium->value);
		$detection->setEnforced(true);
		$detection->setIp(self::EXAMPLE_IP);
		$detection->setActionList([
			['type' => 'ban', 'enforced' => true, 'ref' => ['bans' => [[
				'id' => self::EXAMPLE_BAN,
				'reference' => Ban::formatReference(self::EXAMPLE_REFERENCE),
				'cidr' => self::EXAMPLE_IP . '/32',
				'level' => 1,
				'until' => $now + 14400,
			]], 'counts' => ['banned' => 1, 'already' => 0, 'skipped' => 0]]],
			['type' => 'flag_source', 'enforced' => true, 'ref' => ['until' => $now + 86400]],
			['type' => 'notify_admin', 'enforced' => true, 'ref' => ['recipients' => 2, 'bell' => 'sent', 'email' => 'below_severity']],
		]);
		$detection->setCreatedAt($now);
		$detection->setLastSeenAt($now);
		$detection->setHits(1);
		return $detection;
	}

	private function ban(int $now): Ban {
		$ban = new Ban();
		$ban->setId(self::EXAMPLE_BAN);
		$ban->setReference(self::EXAMPLE_REFERENCE);
		$ban->setCidr(self::EXAMPLE_IP . '/32');
		$ban->setScope(Ban::SCOPE_IP);
		$ban->setLevel(1);
		$ban->setCheckId(CredentialStuffing::ID);
		$ban->setDetectionId(self::EXAMPLE_DETECTION);
		$ban->setCreatedAt($now);
		$ban->setExpiresAt($now + 14400);
		return $ban;
	}
}
