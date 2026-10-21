<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * The remembered browsers (ids_known_devices), one row per account and
 * device fingerprint. Looked up by the unique (uid, device_hmac) index.
 */
class KnownDeviceMapper {
	public const TABLE = 'ids_known_devices';
	private const COLUMNS = ['id', 'uid', 'family', 'platform', 'label', 'net_key', 'created_at', 'last_seen_at'];

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * The account's device with this fingerprint, if it was used after a time.
	 */
	public function find(string $uid, string $deviceHmac, int $usedAfter): ?KnownDevice {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('device_hmac', $qb->createNamedParameter($deviceHmac)))
			->andWhere($qb->expr()->gt('last_seen_at', $qb->createNamedParameter($usedAfter, IQueryBuilder::PARAM_INT)))
			->setMaxResults(1);
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		return is_array($row) ? KnownDevice::fromRow($row) : null;
	}

	public function insert(string $uid, string $deviceHmac, string $family, string $platform, string $label, ?string $netKey, int $now): void {
		$this->db->insertIgnoreConflict(self::TABLE, [
			'uid' => $uid,
			'device_hmac' => $deviceHmac,
			'family' => $family,
			'platform' => $platform,
			'label' => $label,
			'net_key' => $netKey,
			'created_at' => $now,
			'last_seen_at' => $now,
		]);
	}

	public function touch(int $id, int $now): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('last_seen_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->executeStatement();
	}

	/**
	 * @return list<KnownDevice> the account's devices used after a time, most recently used first
	 */
	public function forUser(string $uid, int $usedAfter, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select(...self::COLUMNS)
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->gt('last_seen_at', $qb->createNamedParameter($usedAfter, IQueryBuilder::PARAM_INT)))
			->orderBy('last_seen_at', 'DESC')
			->addOrderBy('id', 'DESC')
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$devices = [];
		while ($row = $result->fetch()) {
			$devices[] = KnownDevice::fromRow($row);
		}
		$result->closeCursor();
		return $devices;
	}

	/**
	 * Keep only the account's most recently used devices.
	 *
	 * @return int how many were removed
	 */
	public function deleteBeyond(string $uid, int $keep): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->orderBy('last_seen_at', 'DESC')
			->addOrderBy('id', 'DESC');
		$result = $qb->executeQuery();
		$ids = [];
		while (($id = $result->fetchOne()) !== false) {
			$ids[] = (int)$id;
		}
		$result->closeCursor();
		// An account has at most a few more than $keep rows, so they are sorted out here.
		$ids = array_slice($ids, $keep);
		if ($ids === []) {
			return 0;
		}
		$delete = $this->db->getQueryBuilder();
		$delete->delete(self::TABLE)
			->where($delete->expr()->in('id', $delete->createNamedParameter($ids, IQueryBuilder::PARAM_INT_ARRAY)));
		return $delete->executeStatement();
	}

	/**
	 * @return bool whether the account had this device
	 */
	public function delete(string $uid, int $id): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		return $qb->executeStatement() > 0;
	}

	public function deleteByHmac(string $uid, string $deviceHmac): bool {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)))
			->andWhere($qb->expr()->eq('device_hmac', $qb->createNamedParameter($deviceHmac)));
		return $qb->executeStatement() > 0;
	}

	/**
	 * Remove all of the account's devices, but the one with this fingerprint.
	 *
	 * @return int how many were removed
	 */
	public function deleteForUser(string $uid, ?string $exceptHmac = null): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		if ($exceptHmac !== null) {
			$qb->andWhere($qb->expr()->neq('device_hmac', $qb->createNamedParameter($exceptHmac)));
		}
		return $qb->executeStatement();
	}

	public function deleteUnusedSince(int $before): int {
		$qb = $this->db->getQueryBuilder();
		$qb->delete(self::TABLE)
			->where($qb->expr()->lte('last_seen_at', $qb->createNamedParameter($before, IQueryBuilder::PARAM_INT)));
		return $qb->executeStatement();
	}
}
