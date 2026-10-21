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
 * The address risk score asks whether an IPv6 network had a trap or
 * reserved-name detection recently. IPv6 detections are matched by their
 * /64 (`net_key`), and merged detections stay open, so the lookup is by
 * `last_seen_at`.
 */
#[AddIndex(table: 'ids_detections', type: IndexType::INDEX, description: 'Recent detections of a network, for the address risk score')]
class Version1000Date20261021110000 extends SimpleMigrationStep {
	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$table = $schema->getTable('ids_detections');
		if ($table->hasIndex('ids_det_net_seen')) {
			return null;
		}
		$table->addIndex(['net_key', 'last_seen_at'], 'ids_det_net_seen');
		return $schema;
	}
}
