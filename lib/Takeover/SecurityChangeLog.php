<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover\AccountTakeoverDetector;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUserSession;
use OCP\Security\ICrypto;
use Psr\Log\LoggerInterface;

/**
 * Records security changes of accounts (concept sections 7 and 10.14) and
 * hands the ones the account holder made to the takeover check.
 *
 * Every change records who made it (`via`): the account holder in their own
 * session, an administrator for someone else, occ, a password reset by
 * email, or the system (background jobs, a public page, this app). Only the
 * account holder's own changes count towards the takeover check.
 *
 * Email addresses are kept masked (f***@example.com). The previous address
 * is also kept encrypted for {@see self::ADDRESS_TTL}, so that the lock link
 * can reach it when the check fires a little after the change.
 */
class SecurityChangeLog implements IPurges {
	public const VIA_SELF = 'self';
	public const VIA_ADMIN = 'admin';
	public const VIA_OCC = 'occ';
	public const VIA_RESET = 'reset';
	public const VIA_SYSTEM = 'system';

	/** The encrypted previous email address is kept this long */
	public const ADDRESS_TTL = 86400;
	/**
	 * Previous email addresses are forgotten for the changes of this period
	 * before their time is up; older ones were forgotten by earlier runs.
	 */
	public const ADDRESS_LOOK_BACK = 7 * 86400;
	/** Token names and provider ids are cut to this length */
	public const MAX_DETAIL = 100;

	public function __construct(
		private readonly SecurityChangeMapper $mapper,
		private readonly ActorResolver $actors,
		private readonly IUserSession $userSession,
		private readonly ResetTracker $resets,
		private readonly CurrentSession $currentSession,
		private readonly RemoteAddressResolver $addresses,
		private readonly AccountTakeoverDetector $detector,
		private readonly ICrypto $crypto,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly AppSettings $settings,
	) {
	}

	/**
	 * Delete the changes past the retention setting of the detections, and
	 * forget the previous email addresses past ADDRESS_TTL.
	 *
	 * @return int how many changes were deleted
	 */
	#[\Override]
	public function purge(int $now): int {
		$deleted = $this->mapper->deleteOlderThan($now - $this->settings->retentionDays() * 86400);
		$this->mapper->forgetAddressesBefore($now - self::ADDRESS_TTL, $now - self::ADDRESS_TTL - self::ADDRESS_LOOK_BACK);
		return $deleted;
	}

	/**
	 * @param ?string $oldAddress the previous email address, for email changes
	 * @param ?string $newAddress the new email address, for email changes
	 * @return int the id of the recorded change
	 */
	public function record(
		string $uid,
		SecurityChangeType $type,
		?string $oldAddress = null,
		?string $newAddress = null,
		?int $refId = null,
		?string $detail = null,
	): int {
		[$via, $actor] = $this->actor($uid);
		$sessionTokenId = $this->actors->isCommandLine() ? null : $this->currentSession->tokenId();
		$source = $this->addresses->current();
		$oldAddress = self::address($oldAddress);
		$newAddress = self::address($newAddress);
		$id = $this->mapper->insert([
			'uid' => $uid,
			'type' => $type->value,
			'via' => $via,
			'actor_uid' => $actor,
			'old_value_hint' => $oldAddress === null ? null : EmailCodes::mask($oldAddress),
			'new_value_hint' => $newAddress === null ? null : EmailCodes::mask($newAddress),
			'notify_to' => $oldAddress === null ? null : $this->crypto->encrypt($oldAddress),
			'ref_id' => $refId,
			'detail' => $detail === null ? null : self::detail($detail),
			'session_token_id' => $sessionTokenId,
			'ip' => $source?->ip,
			'created_at' => $this->timeFactory->getTime(),
		]);

		if ($via === self::VIA_SELF && $type->pointsParam() !== null && ($source === null || !$this->addresses->isBypassListed($source))) {
			try {
				$this->detector->evaluate($uid, $sessionTokenId);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not evaluate the security changes of {uid}', ['uid' => $uid, 'exception' => $e]);
			}
		}
		return $id;
	}

	/**
	 * Who made a change to this account in the current process.
	 *
	 * @return array{0: self::VIA_*, 1: ?string} how, and the acting account if any
	 */
	public function actor(string $uid): array {
		if ($this->actors->isConsole()) {
			return [self::VIA_OCC, null];
		}
		if ($this->actors->isCommandLine()) {
			return [self::VIA_SYSTEM, null];
		}
		if ($this->resets->isResetting($uid)) {
			return [self::VIA_RESET, null];
		}
		$actor = $this->userSession->getUser()?->getUID();
		if ($actor === null) {
			return [self::VIA_SYSTEM, null];
		}
		return [$actor === $uid ? self::VIA_SELF : self::VIA_ADMIN, $actor];
	}

	public static function address(?string $address): ?string {
		$address = trim((string)$address);
		return $address === '' ? null : $address;
	}

	private static function detail(string $detail): string {
		$clean = trim((string)preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $detail));
		return mb_strlen($clean) > self::MAX_DETAIL ? mb_substr($clean, 0, self::MAX_DETAIL - 1) . '…' : $clean;
	}
}
