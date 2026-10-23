<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification\Db;

use OCA\IntrusionDetection\Db\BatchedDelete;
use OCA\IntrusionDetection\Db\IPurges;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IDBConnection;
use OCP\Snowflake\ISnowflakeGenerator;

/**
 * Hourly counters per check and source (ids_alerts). The unique index on
 * (check, source, hour) makes "the first hit of the hour" a single insert
 * that only one web server can win, so an attack becomes one notification
 * with a counter rather than thousands.
 */
class AlertMapper implements IPurges {
	public const TABLE = 'ids_alerts';
	/** Counters are kept as long as their notifications are likely to be read */
	public const RETENTION = 30 * 86400;

	public function __construct(
		private readonly IDBConnection $db,
		private readonly ISnowflakeGenerator $snowflakes,
	) {
	}

	/**
	 * Count one hit.
	 *
	 * @return array{0: string, 1: bool} the counter's id, and whether this was its first hit
	 */
	public function hit(string $checkId, string $sourceKey, int $bucket, ?string $detectionId, int $now): array {
		$id = $this->snowflakes->nextId();
		$inserted = $this->db->insertIgnoreConflict(self::TABLE, [
			'id' => $id,
			'check_id' => $checkId,
			'source_key' => $sourceKey,
			'bucket' => $bucket,
			'hits' => 1,
			'detection_id' => $detectionId,
			'first_at' => $now,
			'last_at' => $now,
		]) > 0;
		if (!$inserted) {
			$qb = $this->db->getQueryBuilder();
			$qb->update(self::TABLE)
				->set('hits', $qb->func()->add('hits', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT)))
				->set('last_at', $qb->createNamedParameter($now, IQueryBuilder::PARAM_INT))
				->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
				->andWhere($qb->expr()->eq('source_key', $qb->createNamedParameter($sourceKey)))
				->andWhere($qb->expr()->eq('bucket', $qb->createNamedParameter($bucket, IQueryBuilder::PARAM_INT)));
			if ($detectionId !== null) {
				$qb->set('detection_id', $qb->createNamedParameter($detectionId));
			}
			$qb->executeStatement();
		}
		return [$inserted ? $id : $this->idOf($checkId, $sourceKey, $bucket), $inserted];
	}

	/**
	 * Remember how many administrators the first notification of a counter went to.
	 */
	public function setRecipients(string $id, int $recipients): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(self::TABLE)
			->set('recipients', $qb->createNamedParameter($recipients, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)))
			->executeStatement();
	}

	/**
	 * @return ?array{id: string, check_id: string, source_key: string, bucket: int, hits: int, detection_id: ?string, first_at: int, last_at: int, recipients: ?int}
	 */
	public function find(string $id): ?array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id', 'check_id', 'source_key', 'bucket', 'hits', 'detection_id', 'first_at', 'last_at', 'recipients')
			->from(self::TABLE)
			->where($qb->expr()->eq('id', $qb->createNamedParameter($id)));
		$result = $qb->executeQuery();
		$row = $result->fetch();
		$result->closeCursor();
		if ($row === false) {
			return null;
		}
		return [
			'id' => (string)$row['id'],
			'check_id' => (string)$row['check_id'],
			'source_key' => (string)$row['source_key'],
			'bucket' => (int)$row['bucket'],
			'hits' => (int)$row['hits'],
			'detection_id' => $row['detection_id'] === null ? null : (string)$row['detection_id'],
			'first_at' => (int)$row['first_at'],
			'last_at' => (int)$row['last_at'],
			'recipients' => $row['recipients'] === null ? null : (int)$row['recipients'],
		];
	}

	#[\Override]
	public function purge(int $now): int {
		return BatchedDelete::run($this->db, self::TABLE, 'id', 'last_at', static fn (IQueryBuilder $qb): IQueryBuilder => $qb->where($qb->expr()->lt('last_at', $qb->createNamedParameter($now - self::RETENTION, IQueryBuilder::PARAM_INT))));
	}

	/**
	 * Whether a counter has a hit already.
	 */
	public function exists(string $checkId, string $sourceKey, int $bucket): bool {
		return $this->idOf($checkId, $sourceKey, $bucket) !== '0';
	}

	/**
	 * The counter's id, "0" when there is none.
	 */
	private function idOf(string $checkId, string $sourceKey, int $bucket): string {
		$qb = $this->db->getQueryBuilder();
		$qb->select('id')
			->from(self::TABLE)
			->where($qb->expr()->eq('check_id', $qb->createNamedParameter($checkId)))
			->andWhere($qb->expr()->eq('source_key', $qb->createNamedParameter($sourceKey)))
			->andWhere($qb->expr()->eq('bucket', $qb->createNamedParameter($bucket, IQueryBuilder::PARAM_INT)));
		$result = $qb->executeQuery();
		$id = $result->fetchOne();
		$result->closeCursor();
		return $id === false ? '0' : (string)$id;
	}
}
