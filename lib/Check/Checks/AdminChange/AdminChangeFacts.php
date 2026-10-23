<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AdminChange;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IFacts;
use OCA\IntrusionDetection\Notification\AdminAlerts;

/**
 * What an administration change detection recorded: the kind of change,
 * who made it, and what it was about. Which facts a change has depends on
 * its kind; the producers of {@see \OCA\IntrusionDetection\Signal\AdminChanged}
 * hand them over as an array that {@see self::fromArray()} reads.
 */
final readonly class AdminChangeFacts implements IFacts {
	/**
	 * @param ?string $kind what changed, one of AdminChange::KIND_*
	 * @param ?string $actor who made the change: an account, or one of the ActorResolver names
	 * @param ?string $actorIp the address of the request that made it
	 * @param ?string $group the group of a membership change
	 * @param ?list<string> $delegated the administration settings delegated to that group
	 * @param ?string $exempt why a new administrator did not wait for approval, one of AdminChange::EXEMPT_*
	 * @param ?int $approval the id of the approval request
	 * @param ?int $expiresAt when that request expires
	 * @param ?string $requestedBy who asked for an approved change
	 * @param ?string $approvedBy who approved it
	 * @param ?bool $reverted the account was taken out of the admin group again to wait for approval
	 * @param ?bool $revertFailed taking it out failed
	 * @param ?string $app the app that was switched on or off
	 * @param ?list<string> $groups the groups the app was switched on for
	 * @param ?string $setting the key of a watched setting that changed
	 * @param ?bool $secret its value is secret, so neither value is recorded
	 * @param ?bool $watch the change was found by the config watch, which cannot know who made it
	 * @param bool $hasValues the values before and after are recorded
	 * @param mixed $old the value before, shortened for display
	 * @param mixed $new the value after, shortened for display
	 * @param ?string $alertKey changes with the same key share one notification per hour
	 * @param ?bool $allAdmins every administrator is told
	 */
	public function __construct(
		public ?string $kind = null,
		public ?string $actor = null,
		public ?string $actorIp = null,
		public ?string $group = null,
		public ?array $delegated = null,
		public ?string $exempt = null,
		public ?int $approval = null,
		public ?int $expiresAt = null,
		public ?string $requestedBy = null,
		public ?string $approvedBy = null,
		public ?bool $reverted = null,
		public ?bool $revertFailed = null,
		public ?string $app = null,
		public ?array $groups = null,
		public ?string $setting = null,
		public ?bool $secret = null,
		public ?bool $watch = null,
		public bool $hasValues = false,
		public mixed $old = null,
		public mixed $new = null,
		public ?string $alertKey = null,
		public ?bool $allAdmins = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'kind'),
			FactValues::string($stored, 'actor'),
			FactValues::string($stored, 'actor_ip'),
			FactValues::string($stored, 'group'),
			FactValues::strings($stored, 'delegated'),
			FactValues::string($stored, 'exempt'),
			FactValues::int($stored, 'approval'),
			FactValues::int($stored, 'expires_at'),
			FactValues::string($stored, 'requested_by'),
			FactValues::string($stored, 'approved_by'),
			FactValues::bool($stored, 'reverted'),
			FactValues::bool($stored, 'revert_failed'),
			FactValues::string($stored, 'app'),
			FactValues::strings($stored, 'groups'),
			FactValues::string($stored, 'setting'),
			FactValues::bool($stored, 'secret'),
			FactValues::bool($stored, 'watch'),
			array_key_exists('old', $stored) || array_key_exists('new', $stored),
			$stored['old'] ?? null,
			$stored['new'] ?? null,
			FactValues::string($stored, AdminAlerts::FACT_ALERT_KEY),
			FactValues::bool($stored, AdminAlerts::FACT_ALL_ADMINS),
			CommonFacts::fromArray($stored),
		);
	}

	/**
	 * These facts as the change of `$kind` by `$actor`, about the account
	 * `$subject`, with the alert it shares.
	 */
	public function of(string $kind, string $actor, ?string $subject, ?string $actorIp, string $alertKey): self {
		return new self(
			$kind,
			$actor,
			$actorIp,
			$this->group,
			$this->delegated,
			$this->exempt,
			$this->approval,
			$this->expiresAt,
			$this->requestedBy,
			$this->approvedBy,
			$this->reverted,
			$this->revertFailed,
			$this->app,
			$this->groups,
			$this->setting,
			$this->secret,
			$this->watch,
			$this->hasValues,
			$this->old,
			$this->new,
			$alertKey,
			true,
			new CommonFacts(targets: $subject === null ? null : [$subject]),
		);
	}

	#[\Override]
	public function toArray(): array {
		$facts = FactValues::recorded([
			'kind' => $this->kind,
			'actor' => $this->actor,
			'group' => $this->group,
			'delegated' => $this->delegated,
			'exempt' => $this->exempt,
			'approval' => $this->approval,
			'expires_at' => $this->expiresAt,
			'requested_by' => $this->requestedBy,
			'approved_by' => $this->approvedBy,
			'reverted' => $this->reverted,
			'revert_failed' => $this->revertFailed,
			'app' => $this->app,
			'groups' => $this->groups,
			'setting' => $this->setting,
			'secret' => $this->secret,
			'watch' => $this->watch,
			'actor_ip' => $this->actorIp,
			AdminAlerts::FACT_ALERT_KEY => $this->alertKey,
			AdminAlerts::FACT_ALL_ADMINS => $this->allAdmins,
		]);
		if ($this->hasValues) {
			// Recorded even when not set: "not set" is a value of a setting.
			$facts['old'] = $this->old;
			$facts['new'] = $this->new;
		}
		return $facts + $this->common->toArray();
	}
}
