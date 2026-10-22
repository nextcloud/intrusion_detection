<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\TrustedNetwork;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\TrustedNetwork\Db\TrustedNetworkMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The networks (/24 for IPv4, /64 for IPv6) users confirmed as their own by
 * answering "Yes, it was me" (concept section 11.8), each for DURATION.
 * Logins from a trusted network skip the extra confirmation for flagged
 * addresses, and login requests started there are not reported as phishing
 * at medium severity.
 *
 * Read only where a decision needs it (a flagged address at login, a login
 * request), with one indexed query.
 */
class TrustedNetworks implements ITrustedNetworks {
	/** Seconds a network stays trusted */
	public const DURATION = 30 * 86400;

	public function __construct(
		private readonly TrustedNetworkMapper $mapper,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	#[\Override]
	public function isTrusted(string $uid, SourceKey $source): bool {
		return $this->mapper->isTrusted($uid, $source->netKey, $this->timeFactory->getTime());
	}

	/**
	 * Trust the network of an address for the account, from now on for
	 * DURATION.
	 *
	 * @return int when the trust ends
	 */
	public function trust(string $uid, SourceKey $source, ?int $detectionId = null): int {
		$now = $this->timeFactory->getTime();
		$until = $now + self::DURATION;
		$this->mapper->trust($uid, $source->netKey, $detectionId, $now, $until);
		$this->audit->log('network %s trusted by %s until %s (detection %s)', ['network' => $source->netKey, 'uid' => $uid, 'until' => (string)$until, 'detection' => $detectionId]);
		return $until;
	}

	/**
	 * @return list<array{id: int, network: string, createdAt: int, expiresAt: int, detectionId: ?int}> the account's trusted networks, newest first
	 */
	public function forUser(string $uid, int $limit = 100): array {
		return array_map(static fn (array $row): array => [
			'id' => $row['id'],
			'network' => $row['net_key'],
			'createdAt' => $row['created_at'],
			'expiresAt' => $row['expires_at'],
			'detectionId' => $row['detection_id'],
		], $this->mapper->findActive($uid, $this->timeFactory->getTime(), $limit));
	}

	/**
	 * Remove one of the account's own entries.
	 *
	 * @return bool whether the account had it
	 */
	public function remove(string $uid, int $id): bool {
		$network = $this->mapper->delete($uid, $id);
		if ($network === null) {
			return false;
		}
		$this->audit->log('trusted network %s removed by %s', ['network' => $network, 'uid' => $uid]);
		return true;
	}

	/**
	 * Stop trusting the network of an address, e.g. after the user said an
	 * event from there was not them.
	 */
	public function distrust(string $uid, SourceKey $source): void {
		if ($this->mapper->deleteNetwork($uid, $source->netKey)) {
			$this->audit->log('trusted network %s of %s removed', ['network' => $source->netKey, 'uid' => $uid]);
		}
	}
}
