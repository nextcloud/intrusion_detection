<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\Security\Guard\GuardDecision;

/**
 * Facts the request guards and the login found, handed to listeners and
 * middleware later in the same request, so nothing is looked up twice.
 * Each fact is kept under a key its owner declares.
 */
class RequestContext {
	private ?GuardDecision $decision = null;
	/** @var array<string, mixed> */
	private array $facts = [];

	/**
	 * Refuse the rest of the request: a hit of a guard that was decided
	 * after the guards ran ({@see DeferredHits}). The first refusal stays.
	 */
	public function refuse(GuardDecision $decision): void {
		$this->decision ??= $decision;
	}

	/**
	 * The refusal decided after the guards ran, if any.
	 */
	public function refusal(): ?GuardDecision {
		return $this->decision;
	}

	public function set(string $key, mixed $value): void {
		$this->facts[$key] = $value;
	}

	public function get(string $key): mixed {
		return $this->facts[$key] ?? null;
	}
}
