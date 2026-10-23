<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

/**
 * Maps the `created_at` column to the `createdTime` property of a snowflake
 * entity, whose getCreatedAt() is the time of its id. The column stays for
 * the queries that select, sort and delete by it through an index.
 */
trait CreatedTimeColumn {
	#[\Override]
	public function columnToProperty(string $columnName): string {
		return $columnName === 'created_at' ? 'createdTime' : (string)parent::columnToProperty($columnName);
	}

	#[\Override]
	public function propertyToColumn(string $property): string {
		return $property === 'createdTime' ? 'created_at' : parent::propertyToColumn($property);
	}
}
