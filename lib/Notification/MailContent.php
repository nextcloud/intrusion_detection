<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCP\Mail\EMailDetails;
use OCP\Mail\IEMailTemplate;

/**
 * The parts of one email, as plain text. {@see Mails} escapes everything and
 * strips control characters when it builds the message.
 */
final class MailContent {
	/**
	 * @param string $templateId identifies the template for theming apps, e.g. "intrusion_detection.alert"
	 * @param list<string> $paragraphs
	 * @param list<string> $listItems shown after the paragraphs, under `$listHeading`
	 * @param list<string> $closing paragraphs after the list, before the button
	 * @param ?string $buttonUrl an absolute link; never one that carries a token
	 * @param list<array{text: string, label: string, type: IEMailTemplate::NOTE_*}> $notes highlighted boxes, shown between the heading and the paragraphs
	 * @param list<EMailDetails> $details cards with labelled rows, shown after the paragraphs
	 */
	public function __construct(
		public readonly string $templateId,
		public readonly string $subject,
		public readonly string $heading,
		public readonly array $paragraphs,
		public readonly string $listHeading = '',
		public readonly array $listItems = [],
		public readonly ?string $buttonText = null,
		public readonly ?string $buttonUrl = null,
		public readonly string $language = '',
		public readonly array $closing = [],
		public readonly array $notes = [],
		public readonly array $details = [],
	) {
	}
}
