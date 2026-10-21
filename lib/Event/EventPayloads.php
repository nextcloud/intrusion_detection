<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Notification\AdminLinks;
use Psr\Log\LoggerInterface;

/**
 * What the typed events send to webhooks (concept section 11.11).
 *
 * Every field is chosen explicitly: identifiers, the check, the severity,
 * what was done, times and a link to the admin page. Never explanations,
 * notes, fingerprints, tokens or secrets. The address is left out when
 * `events_include_ip` is off.
 *
 * Building a payload never throws: webhook_listeners asks for it while the
 * event is dispatched, in the middle of a login or a blocked request.
 */
class EventPayloads {
	public const TYPE_DETECTION = 'detection';
	public const TYPE_BAN_CREATED = 'ban_created';
	public const TYPE_BAN_LIFTED = 'ban_lifted';

	/** Blocks listed per action; webhook_listeners stores the payload in a background job of limited size */
	public const MAX_BANS = 20;

	public function __construct(
		private readonly Settings $settings,
		private readonly AdminLinks $links,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function detection(Detection $detection): array {
		return $this->safely(fn (): array => $this->withIp([
			'type' => self::TYPE_DETECTION,
			'detectionId' => $detection->getId(),
			'checkId' => $detection->getCheckId(),
			'severity' => $detection->getSeverity(),
			'enforced' => $detection->isEnforced(),
		], 'ip', $detection->getIp()) + [
			'uid' => $detection->getUid(),
			'actions' => array_map(self::action(...), $detection->getActionList()),
			'time' => $detection->getCreatedAt(),
			'link' => $this->links->detection($detection->getId()),
		], self::TYPE_DETECTION);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function banCreated(Ban $ban, bool $raised): array {
		return $this->safely(fn (): array => $this->ban($ban, self::TYPE_BAN_CREATED) + [
			'raised' => $raised,
			'level' => $ban->getLevel(),
			'createdBy' => $ban->getCreatedBy(),
			'time' => $ban->getCreatedAt(),
			'expiresAt' => $ban->getExpiresAt(),
		], self::TYPE_BAN_CREATED);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function banLifted(Ban $ban): array {
		return $this->safely(fn (): array => $this->ban($ban, self::TYPE_BAN_LIFTED) + [
			'liftedBy' => $ban->getLiftedBy(),
			'time' => $ban->getLiftedAt(),
			'expiresAt' => $ban->getExpiresAt(),
		], self::TYPE_BAN_LIFTED);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function ban(Ban $ban, string $type): array {
		$detectionId = $ban->getDetectionId();
		return $this->withIp([
			'type' => $type,
			'reference' => $ban->getDisplayReference(),
			'scope' => $ban->getScope(),
		], 'cidr', $ban->getCidr()) + [
			'checkId' => $ban->getCheckId(),
			'detectionId' => $detectionId,
			'link' => $detectionId !== null ? $this->links->detection($detectionId) : $this->links->adminPage() . '#blocks',
		];
	}

	/**
	 * What was done, without the details a handler keeps for the admin page.
	 *
	 * @param array{type: string, enforced: bool, ref?: mixed, note?: string} $action
	 * @return array{type: string, enforced: bool, bans?: list<array{reference: string, expiresAt: int}>}
	 */
	private static function action(array $action): array {
		$public = ['type' => $action['type'], 'enforced' => $action['enforced']];
		$ref = $action['ref'] ?? null;
		if ($action['type'] === 'ban' && is_array($ref) && is_array($ref['bans'] ?? null)) {
			$bans = [];
			foreach (array_slice($ref['bans'], 0, self::MAX_BANS) as $ban) {
				if (is_array($ban) && isset($ban['reference'])) {
					$bans[] = ['reference' => (string)$ban['reference'], 'expiresAt' => (int)($ban['until'] ?? 0)];
				}
			}
			$public['bans'] = $bans;
		}
		return $public;
	}

	/**
	 * @param array<string, mixed> $payload
	 * @return array<string, mixed>
	 */
	private function withIp(array $payload, string $key, ?string $value): array {
		if ($this->settings->getBool(GlobalSettings::EVENTS_INCLUDE_IP)) {
			$payload[$key] = $value;
		}
		return $payload;
	}

	/**
	 * @param \Closure(): array<string, mixed> $build
	 * @return array<string, mixed>
	 */
	private function safely(\Closure $build, string $type): array {
		try {
			return $build();
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not build the {type} event payload', ['type' => $type, 'exception' => $e]);
			return ['type' => $type];
		}
	}
}
