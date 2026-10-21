<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
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
 * Pending logins remembered before their deadline was kept get one: when
 * they started plus `step_up_session_ttl`, so that the background job ends
 * them ({@see \OCA\IntrusionDetection\Confirm\AbandonedLogins}). A
 * session without a deadline is pending only when the login history says
 * so; refused and ended logins keep none.
 */
#[AddColumn(table: 'ids_step_up_sessions', name: 'attempts', type: ColumnType::INTEGER, description: 'Email code tries of the pending login')]
class Version1000Date20261021220000 extends SimpleMigrationStep {
	/** Sessions read at once by the backfill */
	public const BATCH = 500;

	public function __construct(
		private readonly StepUpSessionMapper $sessions,
		private readonly LoginHistoryMapper $history,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
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
		$ttl = $this->settings->getInt(GlobalSettings::STEP_UP_SESSION_TTL);
		$now = $this->timeFactory->getTime();
		$filled = 0;
		$after = '';
		do {
			$rows = $this->sessions->findWithoutDeadline($now, $after, self::BATCH);
			foreach ($rows as $row) {
				$after = $row['session_key'];
				if ($this->history->pendingAround($row['uid'], $row['created_at']) !== null) {
					$this->sessions->setDeadline($row['session_key'], $row['created_at'] + $ttl);
					$filled++;
				}
			}
		} while (count($rows) === self::BATCH);
		if ($filled > 0) {
			$output->info(sprintf('Gave %d waiting logins a deadline', $filled));
		}
	}
}
