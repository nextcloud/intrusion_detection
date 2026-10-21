<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IUser;

/**
 * The browsers users chose to remember after they confirmed a login
 * (concept section 11.5.1).
 *
 * - A device is remembered only after a login was confirmed (an email code
 *   or an administrator's approval) and only when the user ticked
 *   "Remember this device". It gets a new random id in {@see DeviceCookie};
 *   the database holds only its keyed fingerprint ({@see Fingerprinter::device()}).
 * - At a login it is recognised with one indexed read, and its last use is
 *   updated at most once a day, which also renews the cookie.
 * - It is no longer known `known_device_duration` after its last use (at
 *   most MAX_DURATION), when the user removes it, when the user answers
 *   "No, it was not me", when the password changes, and when a credential of
 *   the account is used from two networks at once.
 *
 * An account has at most MAX_PER_USER devices; the least recently used
 * ones are dropped.
 */
class KnownDevices implements IKnownDevices {
	public const MAX_PER_USER = 50;
	public const MAX_DURATION = 180 * 86400;
	/** The last use is written at most this often */
	public const TOUCH_INTERVAL = 86400;

	/** @var array<string, KnownDevice|false> recognised devices of this request, by uid */
	private array $recognised = [];
	/** @var array<int, true> devices whose use was noted in this request */
	private array $touched = [];

	public function __construct(
		private readonly KnownDeviceMapper $mapper,
		private readonly DeviceCookie $cookie,
		private readonly Fingerprinter $fingerprinter,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	public function isEnabled(): bool {
		return $this->settings->getBool(GlobalSettings::KNOWN_DEVICE_ENABLED);
	}

	/**
	 * How long a device stays known after its last use.
	 */
	public function duration(): int {
		return max(86400, min(self::MAX_DURATION, $this->settings->getInt(GlobalSettings::KNOWN_DEVICE_DURATION)));
	}

	/**
	 * The account's remembered device the current request comes from.
	 * One indexed read per account and request, nothing without the cookie.
	 */
	public function recognise(string $uid): ?KnownDevice {
		if (!isset($this->recognised[$uid])) {
			$deviceId = $this->isEnabled() ? $this->cookie->read() : null;
			$device = $deviceId === null
				? null
				: $this->mapper->find($uid, $this->hmac($deviceId), $this->timeFactory->getTime() - $this->duration());
			$this->recognised[$uid] = $device ?? false;
		}
		$device = $this->recognised[$uid];
		return $device === false ? null : $device;
	}

	/**
	 * A recognised device was used: note it once a day, and renew its cookie.
	 */
	public function used(KnownDevice $device): void {
		$now = $this->timeFactory->getTime();
		if ($now - $device->lastSeenAt < self::TOUCH_INTERVAL || isset($this->touched[$device->id])) {
			return;
		}
		$this->touched[$device->id] = true;
		$this->mapper->touch($device->id, $now);
		$deviceId = $this->cookie->read();
		if ($deviceId !== null) {
			$this->cookie->write($deviceId, $now + $this->duration());
		}
	}

	/**
	 * Remember the current browser for the account, after a confirmed login.
	 *
	 * @return bool whether it is remembered now
	 */
	public function remember(IUser $user, ?SourceKey $source, ?string $userAgent): bool {
		if (!$this->isEnabled()) {
			return false;
		}
		$uid = $user->getUID();
		$now = $this->timeFactory->getTime();
		// Always a new id: an old cookie may be a copy that was forgotten for a reason.
		$deviceId = $this->cookie->newId();
		[$family, $platform] = DeviceLabel::parse(UserMessages::shortUserAgent($userAgent));
		$label = DeviceLabel::english($family, $platform);
		$this->mapper->insert($uid, $this->hmac($deviceId), $family, $platform, $label, $source?->netKey, $now);
		$this->mapper->deleteBeyond($uid, self::MAX_PER_USER);
		unset($this->recognised[$uid]);
		if (!$this->cookie->write($deviceId, $now + $this->duration())) {
			$this->mapper->deleteByHmac($uid, $this->hmac($deviceId));
			return false;
		}
		$this->audit->log('device of %s remembered (%s)', ['uid' => $uid, 'device' => $label]);
		return true;
	}

	/**
	 * @return list<array{id: int, label: string, family: string, platform: string, network: ?string, createdAt: int, lastSeenAt: int, current: bool}> most recently used first
	 */
	public function forUser(string $uid, IL10N $l, int $limit = self::MAX_PER_USER): array {
		$current = $this->recognise($uid)?->id;
		return array_map(static fn (KnownDevice $d): array => [
			'id' => $d->id,
			'label' => DeviceLabel::translated($d->family, $d->platform, $l),
			'family' => $d->family,
			'platform' => $d->platform,
			'network' => $d->netKey,
			'createdAt' => $d->createdAt,
			'lastSeenAt' => $d->lastSeenAt,
			'current' => $d->id === $current,
		], $this->mapper->forUser($uid, $this->timeFactory->getTime() - $this->duration(), max(1, min(self::MAX_PER_USER, $limit))));
	}

	/**
	 * Remove one of the account's own devices.
	 *
	 * @return bool whether the account had it
	 */
	public function remove(string $uid, int $id): bool {
		$current = $this->recognise($uid)?->id;
		if (!$this->mapper->delete($uid, $id)) {
			return false;
		}
		unset($this->recognised[$uid]);
		if ($current === $id) {
			$this->cookie->clear();
		}
		$this->audit->log('known device %s of %s removed by the user', ['device' => $id, 'uid' => $uid]);
		return true;
	}

	/**
	 * Forget the account's devices, for example after "No, it was not me".
	 *
	 * @param bool $keepCurrent keep the device the current request comes from
	 * @return int how many were forgotten
	 */
	public function forgetAll(string $uid, string $reason, bool $keepCurrent = false): int {
		$deviceId = $keepCurrent ? $this->cookie->read() : null;
		$forgotten = $this->mapper->deleteForUser($uid, $deviceId === null ? null : $this->hmac($deviceId));
		unset($this->recognised[$uid]);
		if ($forgotten > 0) {
			$this->audit->log('%s known devices of %s forgotten: %s', ['count' => (string)$forgotten, 'uid' => $uid, 'reason' => $reason]);
		}
		return $forgotten;
	}

	#[\Override]
	public function forgetCurrentDevice(string $uid, int $detectionId): void {
		$deviceId = $this->cookie->read();
		if ($deviceId === null || !$this->mapper->deleteByHmac($uid, $this->hmac($deviceId))) {
			return;
		}
		unset($this->recognised[$uid]);
		$this->cookie->clear();
		$this->audit->log('known device of %s forgotten: a credential of the account was used from two networks at once (detection %s)', ['uid' => $uid, 'detection' => $detectionId]);
	}

	public function deleteExpired(): int {
		return $this->mapper->deleteUnusedSince($this->timeFactory->getTime() - $this->duration());
	}

	private function hmac(#[\SensitiveParameter] string $deviceId): string {
		return bin2hex($this->fingerprinter->device($deviceId));
	}
}
