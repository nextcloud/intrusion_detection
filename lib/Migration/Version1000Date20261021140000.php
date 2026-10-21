<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\Attributes\AddIndex;
use OCP\Migration\Attributes\IndexType;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * Indexes and side tables that keep the statistics, the user deletion and
 * the incident reports off full scans.
 */
#[AddIndex(table: 'ids_logins', type: IndexType::INDEX, description: 'Deleting the logins of a deleted account')]
#[AddIndex(table: 'ids_alerts', type: IndexType::INDEX, description: 'Deleting the notification counters of a deleted account')]
class Version1000Date20261021140000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		$logins = $schema->getTable('ids_logins');
		if (!$logins->hasIndex('ids_login_uid')) {
			$logins->addIndex(['uid'], 'ids_login_uid');
		}

		// The unique index starts with check_id, so it does not serve a lookup by source_key alone.
		$alerts = $schema->getTable('ids_alerts');
		if (!$alerts->hasIndex('ids_alert_src')) {
			$alerts->addIndex(['source_key'], 'ids_alert_src');
		}

		return $schema;
	}
}
