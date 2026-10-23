<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AccountLocked;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IFacts;
use OCA\IntrusionDetection\Notification\AdminAlerts;

/**
 * What a lock link detection recorded: the link, the email change it was
 * sent for, and the sessions and app passwords it ended.
 */
final readonly class AccountLockedFacts implements IFacts {
	/**
	 * @param string $link the id of the lock link
	 * @param string $sentTo the masked address it was sent to
	 * @param ?string $newAddress the masked new address, null when it was removed
	 * @param ?int $changedAt when the address was changed
	 * @param ?string $changedFrom the address of the change
	 * @param ?string $takeoverDetection the detection the link was sent for
	 * @param int $tokensEnded the sessions and app passwords that were ended
	 * @param list<array{id: int, name: string}> $ended the first of them
	 * @param ?bool $allAdmins every administrator is told
	 * @param ?bool $keptEnabled the account was the last enabled administrator and stayed enabled
	 */
	public function __construct(
		public string $link = '',
		public string $sentTo = '',
		public ?string $newAddress = null,
		public ?int $changedAt = null,
		public ?string $changedFrom = null,
		public ?string $takeoverDetection = null,
		public int $tokensEnded = 0,
		public array $ended = [],
		public ?bool $allAdmins = null,
		public ?bool $keptEnabled = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'link') ?? '',
			FactValues::string($stored, 'sentTo') ?? '',
			FactValues::string($stored, 'newAddress'),
			FactValues::int($stored, 'changedAt'),
			FactValues::string($stored, 'changedFrom'),
			FactValues::string($stored, 'takeoverDetection'),
			FactValues::int($stored, 'tokensEnded') ?? 0,
			self::ended(FactValues::array($stored, 'ended')),
			FactValues::bool($stored, AdminAlerts::FACT_ALL_ADMINS),
			FactValues::bool($stored, 'keptEnabled'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'link' => $this->link,
			'sentTo' => $this->sentTo,
			'newAddress' => $this->newAddress,
			'changedAt' => $this->changedAt,
			'changedFrom' => $this->changedFrom,
			'takeoverDetection' => $this->takeoverDetection,
			'tokensEnded' => $this->tokensEnded,
			'ended' => $this->ended,
		] + FactValues::recorded([
			AdminAlerts::FACT_ALL_ADMINS => $this->allAdmins,
			'keptEnabled' => $this->keptEnabled,
		]) + $this->common->toArray();
	}

	/**
	 * @param ?array<array-key, mixed> $ended
	 * @return list<array{id: int, name: string}>
	 */
	private static function ended(?array $ended): array {
		$typed = [];
		foreach ($ended ?? [] as $item) {
			if (is_array($item) && is_int($item['id'] ?? null) && is_string($item['name'] ?? null)) {
				$typed[] = ['id' => $item['id'], 'name' => $item['name']];
			}
		}
		return $typed;
	}
}
