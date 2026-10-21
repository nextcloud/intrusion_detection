<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

/**
 * One rule about logged-in sessions, applied by the session-state
 * middleware (AppFramework) and the WebDAV plugin to every request of a
 * logged-in user, in the order of {@see SessionStateRules::RULES}.
 *
 * Rules run on every request, so the path where nothing applies must be
 * cheap: read the session state handed in (or the memory cache), and no
 * database. Rules only take light constructor dependencies, since they are
 * built on every request.
 */
interface ISessionStateRule {
	/**
	 * @return ?SessionBlock why the request may not proceed, or null to let it pass
	 */
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock;
}
