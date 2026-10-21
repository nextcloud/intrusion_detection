<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use Psr\Http\Message\StreamInterface;

/**
 * Where the HTTP client writes a downloaded list. It refuses to take more
 * than its limit, which aborts the transfer at that point, whatever the
 * server claims or compresses: the limit counts the decoded bytes.
 */
final class LimitedSink implements StreamInterface {
	/** @var resource|null */
	private $handle;
	private int $written = 0;

	public function __construct(
		private readonly int $limit,
	) {
		$handle = fopen('php://temp', 'w+b');
		if ($handle === false) {
			throw new \RuntimeException('Cannot open a temporary stream');
		}
		$this->handle = $handle;
	}

	/**
	 * @throws SyncFailure when the limit is exceeded
	 */
	#[\Override]
	public function write(string $string): int {
		if ($this->written + strlen($string) > $this->limit) {
			throw new SyncFailure(SyncFailure::TOO_LARGE);
		}
		$written = fwrite($this->handle(), $string);
		if ($written === false) {
			throw new \RuntimeException('Cannot write to the temporary stream');
		}
		$this->written += $written;
		return $written;
	}

	#[\Override]
	public function __toString(): string {
		try {
			$this->rewind();
			return $this->getContents();
		} catch (\Throwable) {
			return '';
		}
	}

	#[\Override]
	public function close(): void {
		$handle = $this->detach();
		if ($handle !== null) {
			fclose($handle);
		}
	}

	#[\Override]
	public function detach() {
		$handle = $this->handle;
		$this->handle = null;
		return $handle;
	}

	#[\Override]
	public function getSize(): ?int {
		return $this->written;
	}

	#[\Override]
	public function tell(): int {
		$position = ftell($this->handle());
		if ($position === false) {
			throw new \RuntimeException('Cannot tell the position');
		}
		return $position;
	}

	#[\Override]
	public function eof(): bool {
		return feof($this->handle());
	}

	#[\Override]
	public function isSeekable(): bool {
		return $this->handle !== null;
	}

	#[\Override]
	public function seek(int $offset, int $whence = SEEK_SET): void {
		if (fseek($this->handle(), $offset, $whence) !== 0) {
			throw new \RuntimeException('Cannot seek');
		}
	}

	#[\Override]
	public function rewind(): void {
		$this->seek(0);
	}

	#[\Override]
	public function isWritable(): bool {
		return $this->handle !== null;
	}

	#[\Override]
	public function isReadable(): bool {
		return $this->handle !== null;
	}

	#[\Override]
	public function read(int $length): string {
		$data = fread($this->handle(), max(1, $length));
		if ($data === false) {
			throw new \RuntimeException('Cannot read');
		}
		return $data;
	}

	#[\Override]
	public function getContents(): string {
		$data = stream_get_contents($this->handle());
		if ($data === false) {
			throw new \RuntimeException('Cannot read');
		}
		return $data;
	}

	#[\Override]
	public function getMetadata(?string $key = null) {
		$meta = $this->handle === null ? [] : stream_get_meta_data($this->handle);
		return $key === null ? $meta : ($meta[$key] ?? null);
	}

	/**
	 * @return resource
	 */
	private function handle() {
		if ($this->handle === null) {
			throw new \RuntimeException('The stream is closed');
		}
		return $this->handle;
	}
}
