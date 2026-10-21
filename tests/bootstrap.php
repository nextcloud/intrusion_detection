<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

use OCP\App\IAppManager;
use OCP\Server;

// The app is installed in the `apps/` folder of a Nextcloud server checkout.
require_once __DIR__ . '/../../../tests/bootstrap.php';

Server::get(IAppManager::class)->loadApp('intrusion_detection');
