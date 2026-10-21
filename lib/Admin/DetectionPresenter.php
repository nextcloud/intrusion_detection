<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Detections as the admin page lists and explains them.
 *
 * Detections never hold secrets by design. As a second line of defence,
 * everything stored by a check is scrubbed of fields that look like a
 * password, a fingerprint, a token or a secret before it leaves the server.
 *
 * @psalm-import-type IntrusionDetectionDetection from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDetectionDetail from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionAttempt from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionAction from ResponseDefinitions
 */
class DetectionPresenter {
	/** Field names that may carry a secret or a fingerprint; compared without case, "_" and "-" */
	private const SECRET_KEYS = [
		'password', 'passwd', 'pwfp', 'passwordfingerprint', 'fingerprint', 'fingerprints', 'fp',
		'namehmac', 'hmac', 'secret', 'secrethmac', 'token', 'sharetoken', 'credential', 'credkey',
		'apppassword', 'sessionid', 'code', 'devicehmac',
	];
	/** Hex strings of the length of a fingerprint (16 bytes) or an HMAC (32 bytes) */
	private const HEX_SECRET = '/^[0-9a-f]{32}(?:[0-9a-f]{32})?$/i';

	public function __construct(
		private readonly CheckNames $names,
		private readonly NarrativeBuilder $narratives,
		private readonly AttemptMapper $attempts,
		private readonly AddressResolver $addresses,
		private readonly BanPresenter $bans,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionDetection
	 */
	public function row(Detection $detection, IL10N $l): array {
		$checkId = $detection->getCheckId();
		return [
			'id' => (int)$detection->getId(),
			'checkId' => $checkId,
			'checkName' => $this->names->name($checkId, $l),
			'category' => $this->names->category($checkId)->value,
			'severity' => $detection->getSeverity(),
			'enforced' => $detection->isEnforced(),
			'ip' => $detection->getIp(),
			'netKey' => $detection->getNetKey(),
			'uid' => $detection->getUid(),
			'shareId' => $detection->getShareId(),
			'hits' => $detection->getHits(),
			'createdAt' => $detection->getCreatedAt(),
			'lastSeenAt' => $detection->getLastSeenAt(),
			'userVerdict' => $detection->getUserVerdict(),
		];
	}

	/**
	 * @param list<Detection> $detections
	 * @return list<IntrusionDetectionDetection>
	 */
	public function rows(array $detections, IL10N $l): array {
		return array_map(fn (Detection $d): array => $this->row($d, $l), $detections);
	}

	/**
	 * The detection with its narrative, the attempts of its source while
	 * they are still kept, and the blocks that cover its address now.
	 *
	 * @return IntrusionDetectionDetectionDetail
	 */
	public function detail(Detection $detection, IL10N $l): array {
		$narrative = $this->narratives->build($detection, $l);
		$source = $detection->getIp() === null ? null : SourceKey::tryFromIp($detection->getIp());
		$keptSince = $this->timeFactory->getTime() - AttemptRecorder::RETENTION;
		$attemptsAvailable = $source !== null && $detection->getLastSeenAt() >= $keptSince;

		$actions = [];
		foreach ($detection->getActionList() as $action) {
			$actions[] = ['type' => $action['type'], 'enforced' => $action['enforced'], 'note' => $action['note'] ?? null];
		}

		return [
			'detection' => $this->row($detection, $l),
			'explanation' => self::scrub($detection->getExplanationData()),
			'actions' => $actions,
			'narrative' => $narrative->toArray(),
			'text' => $narrative->toText($detection->isEnforced() ? $l->t('What Nextcloud did:') : $l->t('What Nextcloud would have done:')),
			'attemptsAvailable' => $attemptsAvailable,
			'attempts' => $attemptsAvailable ? $this->attempts($source, $keptSince, $l) : [],
			'bans' => $source === null ? [] : $this->bans->presentAll($this->addresses->activeBans($source), $l),
			'risk' => $this->narratives->risk($detection, $l),
		];
	}

	/**
	 * Remove every field that could carry a secret, recursively.
	 *
	 * @param array<array-key, mixed> $data
	 * @return array<array-key, mixed>
	 */
	public static function scrub(array $data): array {
		$clean = [];
		foreach ($data as $key => $value) {
			if (is_string($key) && in_array(strtolower(str_replace(['_', '-'], '', $key)), self::SECRET_KEYS, true)) {
				continue;
			}
			if (is_string($value) && preg_match(self::HEX_SECRET, $value) === 1) {
				continue;
			}
			$clean[$key] = is_array($value) ? self::scrub($value) : $value;
		}
		return array_is_list($data) ? array_values($clean) : $clean;
	}

	/**
	 * @return list<IntrusionDetectionAttempt>
	 */
	private function attempts(SourceKey $source, int $since, IL10N $l): array {
		$attempts = [];
		foreach ($this->attempts->recentForSource($source->ipKey, $since) as $row) {
			$kind = AttemptKind::tryFrom($row['kind']);
			$attempts[] = [
				'kind' => $kind === null ? 'unknown' : self::kindId($kind),
				'label' => $kind === null ? $l->t('Failed attempt') : self::kindLabel($kind, $l),
				'uid' => $row['uid'],
				'createdAt' => $row['created_at'],
			];
		}
		return $attempts;
	}

	private static function kindId(AttemptKind $kind): string {
		return match ($kind) {
			AttemptKind::PasswordLogin => 'password_login',
			AttemptKind::AppPassword => 'app_password',
			AttemptKind::SecondFactor => 'second_factor',
			AttemptKind::UnknownShareToken => 'unknown_share',
			AttemptKind::WrongSharePassword => 'share_password',
			AttemptKind::PasswordReset => 'password_reset',
		};
	}

	private static function kindLabel(AttemptKind $kind, IL10N $l): string {
		return match ($kind) {
			AttemptKind::PasswordLogin => $l->t('Failed password login'),
			AttemptKind::AppPassword => $l->t('Wrong app password or token'),
			AttemptKind::SecondFactor => $l->t('Failed second factor'),
			AttemptKind::UnknownShareToken => $l->t('Unknown share link'),
			AttemptKind::WrongSharePassword => $l->t('Wrong share password'),
			AttemptKind::PasswordReset => $l->t('Password reset request'),
		};
	}
}
