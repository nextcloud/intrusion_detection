<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\Migration\Attributes\AddColumn;
use OCP\Migration\Attributes\ColumnType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * The tries of a pending login's email code, counted on the server, so
 * that parallel requests cannot share one count in the PHP session.
 *
 * Pending logins remembered before their deadline was kept are found by
 * the login history ({@see LoginHistoryMapper::pendingAround()}); refused
 * and ended logins keep no deadline. One still within
 * {@see StepUpService::SESSION_TTL} of its start gets that deadline, so that the
 * background job ends it as usual. One already past it ends quietly, as
 * {@see \OCA\IntrusionDetection\Confirm\AbandonedLogins} ends logins while
 * protection is off: the history says it failed, nobody is told days
 * later, and the row stays so that the session cannot come back.
 */
#[AddColumn(table: 'ids_step_up_sessions', name: 'attempts', type: ColumnType::INTEGER, description: 'Email code tries of the pending login')]
class Version1000Date20261021220000 extends SimpleMigrationStep {
	/** Sessions read at once by the backfill */
	public const BATCH = 500;

	public function __construct(
		private readonly StepUpSessionMapper $sessions,
		private readonly LoginHistoryMapper $history,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		if (!$schema->hasTable('ids_step_up_sessions')) {
			return null;
		}
		$table = $schema->getTable('ids_step_up_sessions');
		if ($table->hasColumn('attempts')) {
			return null;
		}
		$table->addColumn('attempts', Types::INTEGER, ['notnull' => true, 'default' => 0, 'unsigned' => true]);
		return $schema;
	}

	#[\Override]
	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		$ttl = StepUpService::SESSION_TTL;
		$now = $this->timeFactory->getTime();
		$filled = 0;
		$ended = 0;
		$after = '';
		do {
			$rows = $this->sessions->findWithoutDeadline($now, $after, self::BATCH);
			foreach ($rows as $row) {
				$after = $row['session_key'];
				$entry = $this->history->pendingAround($row['uid'], $row['created_at']);
				if ($entry === null) {
					continue;
				}
				$deadline = $row['created_at'] + $ttl;
				if ($deadline > $now) {
					$this->sessions->setDeadline($row['session_key'], $deadline);
					$filled++;
					continue;
				}
				$this->history->setOutcome($entry->id, $row['uid'], LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED);
				$this->audit->log('login of %s ended while upgrading: it was left waiting for its confirmation', ['uid' => $row['uid']]);
				$ended++;
			}
		} while (count($rows) === self::BATCH);
		if ($filled > 0 || $ended > 0) {
			$output->info(sprintf('Waiting logins: %d got a deadline, %d past it were ended quietly', $filled, $ended));
		}
	}
}
