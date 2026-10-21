<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Address\Verdict;
use OCP\Security\Guard\GuardDecision;

/**
 * Facts the request guards found, handed to listeners and middleware later
 * in the same request, so nothing is looked up twice.
 */
class RequestContext {
	private ?Verdict $verdict = null;
	private ?GuardDecision $decision = null;
	/** @var array<string, mixed> */
	private array $facts = [];

	public function setVerdict(Verdict $verdict): void {
		$this->verdict = $verdict;
	}

	/**
	 * The address verdict, if a guard resolved it in this request.
	 */
	public function verdict(): ?Verdict {
		return $this->verdict;
	}

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
