<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Address\Verdict;

/**
 * Facts the request guards found, handed to listeners and middleware later
 * in the same request, so nothing is looked up twice.
 */
class RequestContext {
	private ?Verdict $verdict = null;
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

	public function set(string $key, mixed $value): void {
		$this->facts[$key] = $value;
	}

	public function get(string $key): mixed {
		return $this->facts[$key] ?? null;
	}
}
