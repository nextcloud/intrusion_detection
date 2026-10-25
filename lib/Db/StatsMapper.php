<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;

/**
 * Read-only aggregates for the admin page and the dashboard widget. Every
 * query is bounded by a time window on an indexed column.
 */
class StatsMapper {
	public const DAY = 86400;

	public function __construct(
		private readonly IDBConnection $db,
	) {
	}

	/**
	 * Bans created since a time, lifted or not.
	 *
	 * A ban created since then also ends at or after that time, so the
	 * condition on `expires_at` lets the expiry index narrow the scan.
	 */
	public function bansCreatedSince(int $since): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*', 'n'))
			->from(BanMapper::TABLE)
			->where($qb->expr()->gte('expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Bans created since a time, per check.
	 *
	 * @return array<string, int>
	 */
	public function bansCreatedByCheck(int $since): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id')
			->selectAlias($qb->func()->count('*'), 'n')
			->from(BanMapper::TABLE)
			->where($qb->expr()->gte('expires_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id')
			->orderBy('check_id');
		$result = $qb->executeQuery();
		$counts = [];
		while ($row = $result->fetch()) {
			$counts[(string)$row['check_id']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $counts;
	}

	/**
	 * Distinct accounts that detections since a time were about.
	 */
	public function accountsSince(int $since): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('uid') . ')'))
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->isNotNull('uid'));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Distinct addresses that observed detections since a time would have
	 * blocked: those whose recorded actions include a ban that was not carried out.
	 *
	 * At most `$limit` detections are read; detections of one source are
	 * merged per hour, so that covers even a busy day.
	 */
	public function wouldHaveBlockedSince(int $since, int $limit = 5000): int {
		$qb = $this->db->getQueryBuilder();
		$expr = $qb->expr();
		$qb->select('ip', 'actions')
			->from(DetectionMapper::TABLE)
			->where($expr->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($expr->isNotNull('ip'))
			->andWhere($expr->orX(
				$expr->eq('enforced', $qb->createNamedParameter(false, IQueryBuilder::PARAM_BOOL)),
				$expr->isNull('enforced'),
			))
			->setMaxResults($limit);
		$result = $qb->executeQuery();
		$addresses = [];
		while ($row = $result->fetch()) {
			$detection = new Detection();
			$detection->setActions(is_string($row['actions']) ? $row['actions'] : null);
			foreach ($detection->getActionList() as $action) {
				if ($action['type'] === 'ban' && !$action['enforced']) {
					$addresses[(string)$row['ip']] = true;
					break;
				}
			}
		}
		$result->closeCursor();
		return count($addresses);
	}

	/**
	 * How often each check saw what it detects in [since, until): the hits
	 * of the detections created then, a detection counting every hit merged
	 * into it.
	 *
	 * @return array<string, int> by check id
	 */
	public function hitsPerCheckBetween(int $since, int $until): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('check_id')
			->selectAlias($qb->func()->sum('hits'), 'n')
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->groupBy('check_id');
		$result = $qb->executeQuery();
		$hits = [];
		while ($row = $result->fetch()) {
			$hits[(string)$row['check_id']] = (int)$row['n'];
		}
		$result->closeCursor();
		return $hits;
	}

	/**
	 * Distinct addresses of the detections of some checks created in [since, until).
	 *
	 * @param list<string> $checkIds
	 */
	public function addressesBetween(array $checkIds, int $since, int $until): int {
		if ($checkIds === []) {
			return 0;
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->createFunction('COUNT(DISTINCT ' . $qb->getColumnName('ip') . ')'))
			->from(DetectionMapper::TABLE)
			->where($qb->expr()->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->in('check_id', $qb->createNamedParameter($checkIds, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->isNotNull('ip'));
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * What learning mode held back in [since, until): the detections that
	 * were only observed because of it (not those of checks set to Observe),
	 * and the addresses they would have blocked.
	 *
	 * At most `$limit` detections are read; `complete` is false when there
	 * may have been more.
	 *
	 * @return array{detections: int, addresses: list<string>, complete: bool}
	 */
	public function heldBackByLearning(int $since, ?int $until, int $limit): array {
		$qb = $this->db->getQueryBuilder();
		$expr = $qb->expr();
		$qb->select('ip', 'explanation', 'actions')
			->from(DetectionMapper::TABLE)
			->where($expr->gte('created_at', $qb->createNamedParameter($since, IQueryBuilder::PARAM_INT)))
			->andWhere($expr->orX(
				$expr->eq('enforced', $qb->createNamedParameter(false, IQueryBuilder::PARAM_BOOL)),
				$expr->isNull('enforced'),
			))
			->setMaxResults($limit);
		if ($until !== null) {
			$qb->andWhere($expr->lt('created_at', $qb->createNamedParameter($until, IQueryBuilder::PARAM_INT)));
		}
		$result = $qb->executeQuery();
		$read = 0;
		$detections = 0;
		$addresses = [];
		while ($row = $result->fetch()) {
			$read++;
			$detection = new Detection();
			$detection->setExplanation(is_string($row['explanation']) ? $row['explanation'] : null);
			if (($detection->getExplanationData()['mode']['reason'] ?? null) !== ModeState::REASON_LEARNING) {
				continue;
			}
			$detections++;
			if (!is_string($row['ip']) || $row['ip'] === '') {
				continue;
			}
			$detection->setActions(is_string($row['actions']) ? $row['actions'] : null);
			foreach ($detection->getActionList() as $action) {
				if ($action['type'] === ResponseType::Ban->value && !$action['enforced']) {
					$addresses[$row['ip']] = true;
					break;
				}
			}
		}
		$result->closeCursor();
		return ['detections' => $detections, 'addresses' => array_map('strval', array_keys($addresses)), 'complete' => $read < $limit];
	}
}
