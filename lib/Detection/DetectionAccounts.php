<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionAccountMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * The accounts a detection is about or mentions, kept in a side table when
 * the detection is stored, merged or gets its actions.
 *
 * An account is named by the detection's own account, by the facts in
 * {@see self::FACT_KEYS} and by the action references in
 * {@see self::REF_KEYS}. A check or response that names an account in its
 * facts or references must use one of these keys: deleting the account
 * removes it only from the detections listed here.
 */
class DetectionAccounts {
	/**
	 * Facts that hold an account or a list of accounts. A test reads the
	 * app's code for fact keys that look like they hold one.
	 */
	public const FACT_KEYS = ['targets', 'users', 'actor', 'uid', 'requested_by', 'approved_by', 'owner', 'managers'];
	/** Keys of action references that hold an account */
	public const REF_KEYS = ['uid', 'users'];
	/** Accounts kept per detection at most */
	public const MAX = 200;
	private const UID_MAX_LENGTH = 64;
	private const BACKFILL_BATCH = 500;

	public function __construct(
		private readonly DetectionAccountMapper $mapper,
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * @return list<string>
	 */
	public static function of(Detection $detection): array {
		$uids = [];
		$add = static function (mixed $value) use (&$uids): void {
			foreach (is_array($value) ? $value : [$value] as $uid) {
				if (is_string($uid) && $uid !== '' && strlen($uid) <= self::UID_MAX_LENGTH) {
					$uids[$uid] = true;
				}
			}
		};
		$add($detection->getUid());
		$facts = $detection->getExplanationData()['facts'] ?? null;
		if (is_array($facts)) {
			foreach (self::FACT_KEYS as $key) {
				$add($facts[$key] ?? null);
			}
		}
		foreach ($detection->getActionList() as $action) {
			$ref = $action['ref'] ?? null;
			if (is_array($ref)) {
				foreach (self::REF_KEYS as $key) {
					$add($ref[$key] ?? null);
				}
			}
		}
		return array_slice(array_map('strval', array_keys($uids)), 0, self::MAX);
	}

	/**
	 * @return list<string> the accounts recorded
	 */
	public function recordNew(Detection $detection): array {
		$uids = self::of($detection);
		$this->mapper->addNew($detection->getId(), $uids);
		return $uids;
	}

	/**
	 * Record the accounts a stored detection names now but did not before a
	 * change.
	 *
	 * @param ?list<string> $before {@see self::of()} before the change; null when not known, then the recorded ones are read
	 * @return list<string> the accounts recorded now
	 */
	public function recordChange(Detection $detection, ?array $before): array {
		$now = self::of($detection);
		$added = array_values(array_diff($now, $before ?? $this->mapper->uids($detection->getId())));
		if ($added !== []) {
			$this->mapper->add($detection->getId(), $added);
		}
		return array_values(array_unique(array_merge($before ?? [], $now)));
	}

	/**
	 * Record the accounts of every stored detection, for the detections made
	 * before the side table existed. Accounts already recorded are skipped.
	 */
	public function backfill(): void {
		$lastId = 0;
		do {
			$qb = $this->db->getQueryBuilder();
			$qb->select('id', 'uid', 'explanation', 'actions')
				->from(DetectionMapper::TABLE)
				->where($qb->expr()->gt('id', $qb->createNamedParameter($lastId, IQueryBuilder::PARAM_INT)))
				->orderBy('id', 'ASC')
				->setMaxResults(self::BACKFILL_BATCH);
			$result = $qb->executeQuery();
			$rows = $result->fetchAll();
			$result->closeCursor();
			foreach ($rows as $row) {
				$detection = new Detection();
				$detection->setId((int)$row['id']);
				$detection->setUid($row['uid'] === null ? null : (string)$row['uid']);
				$detection->setExplanation(is_string($row['explanation']) ? $row['explanation'] : null);
				$detection->setActions(is_string($row['actions']) ? $row['actions'] : null);
				$this->mapper->add($detection->getId(), self::of($detection));
				$lastId = $detection->getId();
			}
		} while (count($rows) === self::BACKFILL_BATCH);
	}
}
