<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

use OCP\Config\ValueType;

enum ParamType: string {
	case Int = 'int';
	/** An integer number of seconds */
	case Duration = 'duration';
	case Float = 'float';
	case Bool = 'bool';
	/** One value out of a fixed list of choices */
	case Choice = 'choice';
	/** A list of strings, each optionally validated by a pattern */
	case StringList = 'string_list';
	/** A list of IPv4 or IPv6 CIDR ranges */
	case CidrList = 'cidr_list';
	/** A JSON document, stored as text; the class that owns the setting validates its structure */
	case Json = 'json';

	public function valueType(): ValueType {
		return match ($this) {
			self::Int, self::Duration => ValueType::INT,
			self::Float => ValueType::FLOAT,
			self::Bool => ValueType::BOOL,
			self::Choice, self::Json => ValueType::STRING,
			self::StringList, self::CidrList => ValueType::ARRAY,
		};
	}
}
