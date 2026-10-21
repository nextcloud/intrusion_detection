<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Http\Events\BeforeTemplateRenderedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\Util;

/**
 * Loads the confirm-dialog script on every page of a logged-in user: when
 * a sensitive action is refused with `confirmation_required`, it asks the
 * user to confirm and takes them to the confirm page (concept section
 * 11.13). The script is tiny and needs no translations of its own: the
 * refusal carries its texts.
 *
 * @template-implements IEventListener<BeforeTemplateRenderedEvent>
 */
class ConfirmDialogListener implements IEventListener {
	public const SCRIPT = 'confirm-dialog';

	#[\Override]
	public function handle(Event $event): void {
		if ($event instanceof BeforeTemplateRenderedEvent && $event->isLoggedIn()) {
			Util::addScript(Application::APP_ID, self::SCRIPT);
		}
	}
}
