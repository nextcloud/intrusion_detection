<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IAddsReportNotes;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\ReportNote;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\Constants;
use OCP\IL10N;
use OCP\Share\IManager;
use OCP\Share\IShare;
use Psr\Log\LoggerInterface;

/**
 * Shares the account created in the period, of every type a sharing
 * provider exists for.
 *
 * Only what describes the share is used: its type, the name of the shared
 * item, the recipient (for accounts, groups, email addresses and federated
 * accounts), when it was created and when it expires. Never the share
 * token, the link or the password: a password only shows as "has a
 * password".
 */
class ShareSource implements ITimelineSource, IAddsReportNotes {
	public const KIND = 'share';

	/** Share types whose recipient is a person, a group or an address, not a token */
	private const NAMED_RECIPIENTS = [IShare::TYPE_USER, IShare::TYPE_GROUP, IShare::TYPE_EMAIL, IShare::TYPE_REMOTE, IShare::TYPE_REMOTE_GROUP];
	private const TYPES = [
		IShare::TYPE_USER, IShare::TYPE_GROUP, IShare::TYPE_LINK, IShare::TYPE_EMAIL, IShare::TYPE_REMOTE,
		IShare::TYPE_REMOTE_GROUP, IShare::TYPE_CIRCLE, IShare::TYPE_ROOM, IShare::TYPE_DECK,
	];
	private const PAGE = 500;
	/** At most this many shares of one type are looked at; the report says so when more exist */
	public const SCAN_LIMIT = 5000;

	/** @var \WeakMap<IncidentQuery, true> queries for which not every share could be looked at */
	private \WeakMap $incomplete;

	public function __construct(
		private readonly IManager $shares,
		private readonly DateFormatter $dates,
		private readonly LoggerInterface $logger,
	) {
		$this->incomplete = new \WeakMap();
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('Shares created')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		if ($query->uid === null) {
			return [];
		}
		$entries = [];
		foreach (self::TYPES as $type) {
			foreach ($this->sharesOf($query, $type) as $share) {
				$entries[] = $this->entry($share, $l);
			}
		}
		usort($entries, static fn (TimelineEntry $a, TimelineEntry $b): int => [$a->at, $a->id] <=> [$b->at, $b->id]);
		return array_slice($entries, 0, $query->limit);
	}

	#[\Override]
	public function notesFor(IncidentQuery $query, IL10N $l): array {
		if (!isset($this->incomplete[$query])) {
			return [];
		}
		return [new ReportNote('shares_incomplete', $l->t('The account has more than %s shares of one type. Only the first %s of each type were looked at, so some shares created in this period may be missing.', [(string)self::SCAN_LIMIT, (string)self::SCAN_LIMIT]))];
	}

	/**
	 * The shares of one type the account created in the period.
	 *
	 * @return list<IShare>
	 */
	private function sharesOf(IncidentQuery $query, int $type): array {
		$found = [];
		try {
			for ($offset = 0; $offset < self::SCAN_LIMIT; $offset += self::PAGE) {
				// Expired shares count as well, and are not cleaned up on the way.
				$page = $this->shares->getSharesBy((string)$query->uid, $type, null, false, self::PAGE, $offset, false);
				foreach ($page as $share) {
					$created = $share->getShareTime()->getTimestamp();
					if ($created >= $query->since && $created <= $query->until) {
						$found[] = $share;
					}
				}
				if (count($page) < self::PAGE) {
					return $found;
				}
			}
			$this->incomplete[$query] = true;
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not list the shares of type {type} for an incident report', ['type' => $type, 'exception' => $e]);
		}
		return $found;
	}

	private function entry(IShare $share, IL10N $l): TimelineEntry {
		$name = basename($share->getTarget());
		$type = $share->getShareType();
		$recipient = in_array($type, self::NAMED_RECIPIENTS, true) ? (string)$share->getSharedWith() : '';
		$title = match ($type) {
			IShare::TYPE_LINK => $l->t('Public link to "%s" created', [$name]),
			IShare::TYPE_USER => $l->t('"%1$s" shared with %2$s', [$name, $recipient]),
			IShare::TYPE_GROUP => $l->t('"%1$s" shared with the group %2$s', [$name, $recipient]),
			IShare::TYPE_EMAIL => $l->t('"%1$s" shared by email with %2$s', [$name, $recipient]),
			IShare::TYPE_REMOTE, IShare::TYPE_REMOTE_GROUP => $l->t('"%1$s" shared with %2$s on another server', [$name, $recipient]),
			IShare::TYPE_ROOM => $l->t('"%s" shared in a conversation', [$name]),
			default => $l->t('"%s" shared', [$name]),
		};

		$details = [$share->getNodeType() === 'folder' ? $l->t('A folder.') : $l->t('A file.')];
		$permissions = $share->getPermissions();
		if (($permissions & (Constants::PERMISSION_UPDATE | Constants::PERMISSION_CREATE | Constants::PERMISSION_DELETE)) !== 0) {
			$details[] = $l->t('The recipients can change it.');
		}
		if (in_array($type, [IShare::TYPE_LINK, IShare::TYPE_EMAIL], true)) {
			$details[] = ($share->getPassword() ?? '') !== '' ? $l->t('It has a password.') : $l->t('It has no password.');
		}
		$expires = $share->getExpirationDate();
		if ($expires !== null) {
			$details[] = $l->t('Expiry date: %s.', [$this->dates->dateTime($expires->getTimestamp())]);
		}

		return new TimelineEntry(
			id: 'share:' . $share->getFullId(),
			at: $share->getShareTime()->getTimestamp(),
			kind: self::KIND,
			group: $l->t('Shares created'),
			title: $title,
			details: $details,
			accounts: $type === IShare::TYPE_USER && $recipient !== '' ? [$recipient] : [],
			ref: ['type' => 'share', 'id' => $share->getFullId()],
			categories: [DataCategory::SharedFiles],
			followUp: $l->t('Check the shares created in this period with the account owner, and delete the ones they did not make.'),
		);
	}
}
