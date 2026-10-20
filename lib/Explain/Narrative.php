<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

/**
 * The rendered explanation of one detection: what happened, what Nextcloud
 * did (or would have done), and why it only observed if it did.
 */
final class Narrative {
	/**
	 * @param list<string> $happened
	 * @param list<string> $done
	 */
	public function __construct(
		public readonly string $title,
		public readonly array $happened,
		public readonly array $done,
		public readonly ?string $observedBecause,
	) {
	}

	/**
	 * @return array{title: string, happened: list<string>, done: list<string>, observedBecause: ?string}
	 */
	public function toArray(): array {
		return [
			'title' => $this->title,
			'happened' => $this->happened,
			'done' => $this->done,
			'observedBecause' => $this->observedBecause,
		];
	}

	public function toText(string $doneHeading): string {
		$lines = [$this->title, ''];
		foreach ($this->happened as $sentence) {
			$lines[] = $sentence;
		}
		$lines[] = '';
		$lines[] = $doneHeading;
		foreach ($this->done as $sentence) {
			$lines[] = '- ' . $sentence;
		}
		if ($this->observedBecause !== null) {
			$lines[] = '';
			$lines[] = $this->observedBecause;
		}
		return implode("\n", $lines);
	}
}
