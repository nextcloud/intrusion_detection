<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

enum AttemptKind: int {
	case PasswordLogin = 1;
	case AppPassword = 2;
	case SecondFactor = 3;
	case UnknownShareToken = 4;
	case WrongSharePassword = 5;
	case PasswordReset = 6;
}
