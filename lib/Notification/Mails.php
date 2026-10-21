<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCP\IUser;
use OCP\Mail\EMailDetails;
use OCP\Mail\EMailDetailsRow;
use OCP\Mail\IEmailValidator;
use OCP\Mail\IMailer;
use Psr\Log\LoggerInterface;

/**
 * Sends the app's emails to users and administrators through core's mailer
 * and themed email template.
 *
 * Every text goes through the template, which escapes it for HTML; control
 * characters are removed and long texts cut first. People without an email
 * address are a normal case: nothing is sent and false is returned, so the
 * caller can fall back to what it does for them.
 */
class Mails {
	public const MAX_TEXT = 2000;

	public function __construct(
		private readonly IMailer $mailer,
		private readonly IEmailValidator $emailValidator,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return bool whether the email was handed to the mail server
	 */
	public function send(IUser $recipient, MailContent $content): bool {
		$address = $recipient->getEMailAddress();
		if ($address === null || $address === '' || !$this->emailValidator->isValid($address)) {
			return false;
		}
		try {
			$template = $this->mailer->createEMailTemplate($content->templateId, []);
			if ($content->language !== '') {
				$template->setLanguage($content->language);
			}
			$template->setSubject(self::clean($content->subject));
			$template->addHeader();
			$template->addHeading(self::clean($content->heading));
			foreach ($content->notes as $note) {
				$template->addBodyNote(self::clean($note['text']), self::clean($note['label']), $note['type']);
			}
			foreach ($content->paragraphs as $paragraph) {
				$template->addBodyText(self::clean($paragraph));
			}
			foreach ($content->details as $details) {
				$template->addBodyDetails(self::cleanDetails($details));
			}
			if ($content->listItems !== []) {
				if ($content->listHeading !== '') {
					$template->addBodyText(self::clean($content->listHeading));
				}
				foreach ($content->listItems as $item) {
					$template->addBodyListItem(self::clean($item));
				}
			}
			foreach ($content->closing as $paragraph) {
				$template->addBodyText(self::clean($paragraph));
			}
			if ($content->buttonText !== null && $content->buttonUrl !== null) {
				$template->addBodyButton(self::clean($content->buttonText), $content->buttonUrl);
			}
			$template->addFooter('', $content->language !== '' ? $content->language : null);

			$message = $this->mailer->createMessage();
			$message->setTo([$address => self::clean($recipient->getDisplayName())]);
			$message->useTemplate($template);
			return $this->mailer->send($message) === [];
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not send an email to {uid}', [
				'uid' => $recipient->getUID(),
				'exception' => $e,
			]);
			return false;
		}
	}

	/**
	 * A copy of the card with every text cleaned like {@see clean()}.
	 */
	private static function cleanDetails(EMailDetails $details): EMailDetails {
		$clean = new EMailDetails(self::clean($details->getTitle()));
		$clean->setSubtitle(self::clean($details->getSubtitle()));
		foreach ($details->getRows() as $row) {
			$cleanRow = $clean->addRow(self::clean($row->getLabel()));
			foreach ($row->getParts() as $part) {
				match ($part['type']) {
					EMailDetailsRow::PART_LINK => $cleanRow->link(self::clean($part['text']), $part['url']),
					EMailDetailsRow::PART_MUTED => $cleanRow->muted(self::clean($part['text'])),
					default => $cleanRow->text(self::clean($part['text'])),
				};
			}
		}
		return $clean;
	}

	/**
	 * One line of plain text: control characters become spaces, and the text
	 * is cut to MAX_TEXT characters.
	 */
	public static function clean(string $text): string {
		// Without the u modifier as a fallback for text that is not valid UTF-8.
		$clean = preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $text) ?? preg_replace('/[\x00-\x1f\x7f]+/', ' ', $text) ?? '';
		$clean = trim($clean);
		return mb_strlen($clean) > self::MAX_TEXT ? mb_substr($clean, 0, self::MAX_TEXT - 1) . '…' : $clean;
	}
}
