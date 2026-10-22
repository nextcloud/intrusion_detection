<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Share;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforce;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IURLGenerator;
use OCP\Share\Exceptions\ShareNotFound;
use OCP\Share\IManager as IShareManager;
use OCP\Share\IShare;
use Psr\Container\ContainerInterface;

/**
 * The shares that share link detections are about: finding them again,
 * who may manage them, and turning a link off for its owner.
 *
 * Detections store the share's id, never its token or its name; the name
 * is read from the share when a text needs it.
 */
class ShareLinks {
	public const DISABLED = 'disabled';
	public const ALREADY_GONE = 'already_gone';
	public const NOT_FOUND = 'not_found';

	/** Share types whose link "Disable link" turns off */
	public const LINK_TYPES = [IShare::TYPE_LINK, IShare::TYPE_EMAIL];

	private ?IShareManager $shareManager = null;

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly DetectionMapper $detections,
		private readonly IURLGenerator $urlGenerator,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * The share a detection is about, or null when it no longer exists.
	 */
	public function find(Detection $detection): ?IShare {
		$fullId = self::fullId($detection);
		if ($fullId === null) {
			return null;
		}
		try {
			$share = $this->manager()->getShareById($fullId, null, false);
		} catch (ShareNotFound) {
			return null;
		}
		return $share->getId() === (string)$detection->getShareId() ? $share : null;
	}

	/**
	 * The accounts that may manage a share: the one who created the link,
	 * and the owner of the shared file if that is someone else.
	 *
	 * @return list<string>
	 */
	public function managers(IShare $share): array {
		return array_values(array_unique(array_filter(
			[(string)$share->getSharedBy(), (string)$share->getShareOwner()],
			static fn (string $uid): bool => $uid !== '',
		)));
	}

	public function canManage(IShare $share, string $uid): bool {
		return in_array($uid, $this->managers($share), true);
	}

	/**
	 * The label of the share, or the name of the shared file or folder.
	 */
	public function displayName(IShare $share): string {
		$label = trim((string)$share->getLabel());
		if ($label !== '') {
			return $label;
		}
		return basename((string)$share->getTarget());
	}

	/**
	 * The shared file in the Files app, with its details (and sharing settings) open.
	 */
	public function settingsLink(IShare $share): string {
		return $this->urlGenerator->linkToRouteAbsolute('files.View.showFile', [
			'fileid' => (string)$share->getNodeId(),
			'opendetails' => 'true',
		]);
	}

	public function isLink(IShare $share): bool {
		return in_array($share->getShareType(), self::LINK_TYPES, true);
	}

	/**
	 * "Disable link" from the owner's notification: delete the link share of
	 * a share_bruteforce detection, if the acting account may manage it.
	 *
	 * Doing it twice is harmless: a share that is already gone reports
	 * ALREADY_GONE. Everything that is not the actor's own share link reports
	 * NOT_FOUND, so the answer reveals nothing about other people's shares.
	 *
	 * @return self::DISABLED|self::ALREADY_GONE|self::NOT_FOUND
	 */
	public function disable(int $detectionId, string $actorUid): string {
		try {
			$detection = $this->detections->findById($detectionId);
		} catch (DoesNotExistException) {
			return self::NOT_FOUND;
		}
		if ($detection->getCheckId() !== ShareBruteforce::ID || $detection->getShareId() === null) {
			return self::NOT_FOUND;
		}
		$share = $this->find($detection);
		if ($share === null) {
			// Only the people the detection told may learn that the link is gone.
			return in_array($actorUid, DetectionFacts::of($detection)->list('managers'), true) ? self::ALREADY_GONE : self::NOT_FOUND;
		}
		if (!$this->canManage($share, $actorUid) || !$this->isLink($share)) {
			return self::NOT_FOUND;
		}
		$this->manager()->deleteShare($share);
		$this->audit->log('share link %s disabled by %s from an intrusion detection notification (detection %s)', [
			'share' => $share->getFullId(),
			'actor' => $actorUid,
			'detection' => $detectionId,
		]);
		return self::DISABLED;
	}

	/**
	 * "ocinternal:42": the provider and id the detection recorded.
	 */
	private static function fullId(Detection $detection): ?string {
		$shareId = $detection->getShareId();
		if ($shareId === null) {
			return null;
		}
		$fullId = DetectionFacts::of($detection)->string('share');
		if (preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}:(\d{1,20})$/', $fullId, $m) === 1 && $m[1] === (string)$shareId) {
			return $fullId;
		}
		return 'ocinternal:' . $shareId;
	}

	/**
	 * Resolved on first use: this class is built whenever detections are
	 * explained, and most explanations never touch a share.
	 */
	private function manager(): IShareManager {
		return $this->shareManager ??= $this->container->get(IShareManager::class);
	}
}
