<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

/**
 * A controller of the app that is a page of the login flow: the session
 * rules know it by its route, not by its class.
 */
interface ILoginFlowPage {
	public static function loginFlowRoute(): LoginFlowRoute;
}
