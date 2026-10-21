<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Privacy;

use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Db\ResetSuppressionMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Db\TrustedNetworkMapper;
use OCA\IntrusionDetection\Db\UserDailyMapper;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Removes a deleted account from everything the app stores. This is the one
 * place that knows which table holds what about an account; a table with
 * account data is added to DELETE or ANONYMISE.
 *
 * - DELETE: rows that only exist for the account are deleted.
 * - ANONYMISE: rows that still count for other purposes (failed attempts
 *   count against their address) keep existing without the account.
 * - Detections keep explaining what happened, without the account: their
 *   account is set to null, and the account is removed from the facts
 *   (the targets of an attack) and from the recorded actions.
 * - The counters that aggregate notifications about the account are deleted.
 *
 * The app's user settings and notifications are removed by core.
 */
class UserDataCleanup {
	/** @var array<string, string> table => the column that holds the uid */
	public const DELETE = [
		TokenOriginMapper::TABLE => 'uid',
		ProtectedAccountMapper::TABLE => 'uid',
		LoginMapper::TABLE => 'uid',
		ResetSuppressionMapper::TABLE => 'uid',
		// Requests about the account; who requested or decided one stays, like a block's creator.
		ApprovalMapper::TABLE => 'subject_uid',
		TrustedNetworkMapper::TABLE => 'uid',
		StepUpSessionMapper::TABLE => 'uid',
		KnownDeviceMapper::TABLE => 'uid',
		LoginHistoryMapper::TABLE => 'uid',
		SecurityChangeMapper::TABLE => 'uid',
		LockLinkMapper::TABLE => 'uid',
		UserDailyMapper::TABLE => 'uid',
	];

	/** @var array<string, string> table => the column set to null */
	public const ANONYMISE = [
		AttemptMapper::TABLE => 'uid',
	];

	/** Detections are rewritten in batches of this size */
	public const BATCH = 200;

	public function __construct(
		private readonly IDBConnection $db,
		private readonly DetectionMapper $detections,
	) {
	}

	public function deleteUser(string $uid): void {
		foreach (self::DELETE as $table => $column) {
			$qb = $this->db->getQueryBuilder();
			$qb->delete($table)
				->where($qb->expr()->eq($column, $qb->createNamedParameter($uid)))
				->executeStatement();
		}
		foreach (self::ANONYMISE as $table => $column) {
			$qb = $this->db->getQueryBuilder();
			$qb->update($table)
				->set($column, $qb->createNamedParameter(null, IQueryBuilder::PARAM_NULL))
				->where($qb->expr()->eq($column, $qb->createNamedParameter($uid)))
				->executeStatement();
		}
		$this->deleteCounters($uid);
		$this->scrubDetections($uid);
	}

	private function deleteCounters(string $uid): void {
		$keys = ['u:' . $uid, ...UserAlerts::counterKeys($uid)];
		foreach (AdminNotices::KEY_PREFIXES as $prefix) {
			$keys[] = $prefix . $uid;
		}
		$qb = $this->db->getQueryBuilder();
		$qb->delete(AlertMapper::TABLE)
			->where($qb->expr()->in('source_key', $qb->createNamedParameter($keys, IQueryBuilder::PARAM_STR_ARRAY)))
			->executeStatement();
	}

	/**
	 * Detections of the account, and detections whose explanation or actions
	 * mention it (as a target of an attack), are rewritten without it.
	 */
	private function scrubDetections(string $uid): void {
		$jsonUid = json_encode($uid, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		$lastId = 0;
		do {
			$batch = $this->detections->findMentioning($uid, $jsonUid, $lastId, self::BATCH);
			foreach ($batch as $detection) {
				$lastId = $detection->getId();
				$this->scrub($detection, $uid);
			}
		} while (count($batch) === self::BATCH);
	}

	private function scrub(Detection $detection, string $uid): void {
		if ($detection->getUid() === $uid) {
			$detection->setUid(null);
			// The merge key was derived from the account: no later hit may join this row.
			$detection->setMergeKey(null);
		}
		$explanation = $detection->getExplanationData();
		if (is_array($explanation['facts'] ?? null)) {
			$explanation['facts'] = self::without($explanation['facts'], $uid);
			$detection->setExplanationData($explanation);
		}
		$actions = [];
		foreach ($detection->getActionList() as $action) {
			if (isset($action['ref'])) {
				$action['ref'] = is_array($action['ref']) ? self::without($action['ref'], $uid) : ($action['ref'] === $uid ? null : $action['ref']);
			}
			$actions[] = $action;
		}
		$detection->setActionList($actions);
		$this->detections->update($detection);
	}

	/**
	 * The data without the account: list entries equal to the uid are
	 * dropped, other values equal to it become null.
	 *
	 * @param array<array-key, mixed> $data
	 * @return array<array-key, mixed>
	 */
	public static function without(array $data, string $uid): array {
		$isList = array_is_list($data);
		$clean = [];
		foreach ($data as $key => $value) {
			if (is_array($value)) {
				$value = self::without($value, $uid);
			} elseif ($value === $uid) {
				if ($isList) {
					continue;
				}
				$value = null;
			}
			$clean[$key] = $value;
		}
		return $isList ? array_values($clean) : $clean;
	}
}
