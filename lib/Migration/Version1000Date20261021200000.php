<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\DB\Types;
use OCP\IAppConfig;
use OCP\Migration\Attributes\AddColumn;
use OCP\Migration\Attributes\ColumnType;
use OCP\Migration\Attributes\CreateTable;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;

/**
 * - Which attempts a browser may have made for another site or an email, so
 *   that they never make an address a target of a block.
 * - Internal state the app writes often, out of the app config: every app
 *   config write drops core's cached app config.
 */
#[AddColumn(table: 'ids_attempts', name: 'lure', type: ColumnType::BOOLEAN, description: 'True when the attempt may have been a lure (a request a browser made for another site); null otherwise')]
#[CreateTable(table: 'ids_state', description: 'Internal state written often: the verdict cache version, the firewall export state')]
class Version1000Date20261021200000 extends SimpleMigrationStep {
	/** App config keys whose state moved to ids_state */
	private const MOVED_KEYS = ['export_state', 'ban_version'];

	public function __construct(
		private readonly IAppConfig $appConfig,
	) {
	}

	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options): ?ISchemaWrapper {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();
		$changed = false;
		if ($schema->hasTable('ids_attempts')) {
			$table = $schema->getTable('ids_attempts');
			if (!$table->hasColumn('lure')) {
				$table->addColumn('lure', Types::BOOLEAN, ['notnull' => false, 'default' => null]);
				$changed = true;
			}
		}
		if (!$schema->hasTable('ids_state')) {
			$table = $schema->createTable('ids_state');
			$table->addColumn('name', Types::STRING, ['notnull' => true, 'length' => 64]);
			$table->addColumn('value', Types::TEXT, ['notnull' => false]);
			$table->setPrimaryKey(['name']);
			$changed = true;
		}
		return $changed ? $schema : null;
	}

	/**
	 * @param Closure(): ISchemaWrapper $schemaClosure
	 */
	#[\Override]
	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		foreach (self::MOVED_KEYS as $key) {
			$this->appConfig->deleteKey('intrusion_detection', $key);
		}
	}
}
