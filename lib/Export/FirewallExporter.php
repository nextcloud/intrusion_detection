<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ISecureRandom;
use Psr\Log\LoggerInterface;

/**
 * Writes the active blocks for firewalls and fail2ban into the export
 * directory ({@see ExportDirectory}). The app never runs a firewall command
 * itself; root-owned loaders pick the files up ({@see FirewallSnippets}).
 *
 * - `bans.txt`, `bans.nft`, `bans.ipset` are rewritten from the active blocks
 *   on every block change and when a block ended. Each is written to a new
 *   temporary file and renamed into place, so a reader never sees half a file.
 * - `bans.log` is appended to, one line per block and lift, and rotated to
 *   `bans.log.1` at 10 MB.
 *
 * Nothing is written while `intrusion_detection.export_dir` is unset or no
 * format is switched on. Failures are recorded for the admin page, never thrown
 * at the request that changed a block.
 */
class FirewallExporter {
	public const LOG_ROTATE_BYTES = 10 * 1024 * 1024;
	/** At most this many blocks are exported */
	public const MAX_ENTRIES = 50000;
	/** Further block changes within this many seconds are written once, at the end of the request */
	private const COALESCE_SECONDS = 2.0;
	private const FILE_MODE = 0o640;

	private ?float $lastSnapshot = null;
	private bool $pending = false;
	private bool $shutdownRegistered = false;

	public function __construct(
		private readonly ExportDirectory $directory,
		private readonly Settings $settings,
		private readonly BanMapper $bans,
		private readonly ITimeFactory $timeFactory,
		private readonly ISecureRandom $random,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return list<ExportFormat>
	 */
	public function formats(): array {
		$values = $this->settings->global(GlobalSettings::EXPORT_FORMATS);
		$formats = [];
		foreach (is_array($values) ? $values : [] as $value) {
			$format = ExportFormat::tryFrom($value);
			if ($format !== null) {
				$formats[] = $format;
			}
		}
		return $formats;
	}

	public function isActive(): bool {
		return $this->directory->configured() !== null && $this->formats() !== [];
	}

	public function status(): ExportStatus {
		$state = $this->settings->getJson(GlobalSettings::EXPORT_STATE);
		$error = is_string($state['error'] ?? null) ? $state['error'] : null;
		if ($this->directory->configured() === null) {
			$error = ExportException::NOT_CONFIGURED;
		}
		return new ExportStatus(
			$this->directory->configured(),
			$this->formats(),
			is_int($state['last_write_at'] ?? null) ? $state['last_write_at'] : null,
			$error,
			is_int($state['error_at'] ?? null) ? $state['error_at'] : null,
			is_int($state['entries'] ?? null) ? $state['entries'] : 0,
		);
	}

	/**
	 * A block was created, raised or lifted: log it and rewrite the files.
	 * Never throws.
	 */
	public function banChanged(Ban $ban, bool $lifted): void {
		if (!$this->isActive()) {
			return;
		}
		$now = $this->timeFactory->getTime();
		if (in_array(ExportFormat::Log, $this->formats(), true)) {
			try {
				$this->appendLog($this->directory->resolve(), $lifted ? ExportRenderer::liftLine($ban, $now) : ExportRenderer::banLine($ban, $now));
			} catch (ExportException $e) {
				$this->recordError($e->reason, $now);
			}
		}
		$this->scheduleSnapshot();
	}

	/**
	 * Rewrite the snapshot files now.
	 *
	 * @throws ExportException when the directory cannot be used or a file cannot be written
	 */
	public function write(): ExportStatus {
		$now = $this->timeFactory->getTime();
		$this->lastSnapshot = microtime(true);
		$this->pending = false;
		try {
			$dir = $this->directory->resolve();
			$entries = $this->entries($now);
			foreach ($this->formats() as $format) {
				if ($format->isSnapshot()) {
					$this->writeAtomically($dir . '/' . $format->fileName(), ExportRenderer::render($format, $entries, $now));
				}
			}
		} catch (ExportException $e) {
			$this->recordError($e->reason, $now);
			throw $e;
		}
		$this->settings->setGlobal(GlobalSettings::EXPORT_STATE, json_encode([
			'last_write_at' => $now,
			'error' => null,
			'error_at' => null,
			'entries' => count($entries),
			'next_expiry' => self::nextChange($entries, $now),
			'signature' => $this->signature(),
		]));
		return $this->status();
	}

	/**
	 * For the background job: rewrite only when a block ended (or an ipset
	 * timeout ran out) since the last write, or the directory or formats
	 * changed. Otherwise nothing is read or written.
	 *
	 * @return bool whether the files were written
	 */
	public function writeIfDue(): bool {
		if (!$this->isActive()) {
			return false;
		}
		$state = $this->settings->getJson(GlobalSettings::EXPORT_STATE);
		$nextExpiry = is_int($state['next_expiry'] ?? null) ? $state['next_expiry'] : 0;
		$due = !is_int($state['last_write_at'] ?? null)
			|| ($state['signature'] ?? null) !== $this->signature()
			|| ($nextExpiry > 0 && $this->timeFactory->getTime() >= $nextExpiry);
		if (!$due) {
			return false;
		}
		try {
			$this->write();
		} catch (ExportException) {
			// Recorded in the status.
		}
		return true;
	}

	/**
	 * Rewrite at once, or, when the files were written moments ago in this
	 * request (a burst of blocks), once more at the end of the request.
	 */
	private function scheduleSnapshot(): void {
		if ($this->lastSnapshot !== null && microtime(true) - $this->lastSnapshot < self::COALESCE_SECONDS) {
			$this->pending = true;
			if (!$this->shutdownRegistered) {
				$this->shutdownRegistered = true;
				register_shutdown_function(function (): void {
					if ($this->pending) {
						$this->writeQuietly();
					}
				});
			}
			return;
		}
		$this->writeQuietly();
	}

	private function writeQuietly(): void {
		try {
			$this->write();
		} catch (ExportException) {
			// Recorded in the status.
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not write the firewall export', ['exception' => $e]);
		}
	}

	/**
	 * @return list<ExportEntry>
	 */
	private function entries(int $now): array {
		$entries = [];
		foreach ($this->bans->findList($now, false, self::MAX_ENTRIES) as $ban) {
			try {
				$entries[] = ExportEntry::fromBan($ban);
			} catch (\InvalidArgumentException) {
				$this->logger->warning('Intrusion detection skipped a block with an invalid range in the firewall export', ['ban' => $ban->getId()]);
			}
		}
		return ExportEntry::sort($entries);
	}

	/**
	 * When the files must be written again at the latest: the first block
	 * that ends, or the first ipset timeout that runs out. 0 when nothing is blocked.
	 *
	 * @param list<ExportEntry> $entries
	 */
	private static function nextChange(array $entries, int $now): int {
		$next = 0;
		foreach ($entries as $entry) {
			$at = min($entry->expiresAt, $now + ExportRenderer::IPSET_MAX_TIMEOUT);
			$next = $next === 0 ? $at : min($next, $at);
		}
		return $next;
	}

	/**
	 * @throws ExportException
	 */
	private function writeAtomically(string $path, string $content): void {
		$temp = dirname($path) . '/.' . basename($path) . '.' . $this->random->generate(12, ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS) . '.tmp';
		// "x" refuses to open an existing path, including a symbolic link someone placed there.
		$handle = @fopen($temp, 'xb');
		if ($handle === false) {
			throw new ExportException(ExportException::WRITE_FAILED);
		}
		$written = fwrite($handle, $content);
		$flushed = fflush($handle);
		fclose($handle);
		if ($written !== strlen($content) || !$flushed || !@chmod($temp, self::FILE_MODE) || !@rename($temp, $path)) {
			@unlink($temp);
			throw new ExportException(ExportException::WRITE_FAILED);
		}
	}

	/**
	 * @throws ExportException
	 */
	private function appendLog(string $dir, string $line): void {
		$path = $dir . '/' . ExportFormat::Log->fileName();
		for ($attempt = 0; $attempt < 3; $attempt++) {
			$handle = @fopen($path, 'ab');
			if ($handle === false) {
				throw new ExportException(ExportException::WRITE_FAILED);
			}
			try {
				if (!flock($handle, LOCK_EX)) {
					throw new ExportException(ExportException::WRITE_FAILED);
				}
				// Another process may have rotated the file while this one waited for the lock.
				clearstatcache(true, $path);
				$open = fstat($handle);
				$current = @stat($path);
				if ($open === false || $current === false || $open['ino'] !== $current['ino']) {
					continue;
				}
				if ($open['size'] >= self::LOG_ROTATE_BYTES) {
					@rename($path, $path . '.1');
					continue;
				}
				@chmod($path, self::FILE_MODE);
				if (fwrite($handle, $line) !== strlen($line)) {
					throw new ExportException(ExportException::WRITE_FAILED);
				}
				fflush($handle);
				return;
			} finally {
				flock($handle, LOCK_UN);
				fclose($handle);
			}
		}
		throw new ExportException(ExportException::WRITE_FAILED);
	}

	private function recordError(string $reason, int $now): void {
		$state = $this->settings->getJson(GlobalSettings::EXPORT_STATE);
		if (($state['error'] ?? null) === $reason) {
			return;
		}
		$state['error'] = $reason;
		$state['error_at'] = $now;
		$this->settings->setGlobal(GlobalSettings::EXPORT_STATE, json_encode($state));
		$this->logger->warning('Intrusion detection could not write the firewall export: {reason}', ['reason' => $reason]);
	}

	/**
	 * Changes when the directory or the formats change, so the job rewrites then.
	 */
	private function signature(): string {
		return hash('sha256', ($this->directory->configured() ?? '') . "\0" . implode(',', array_map(static fn (ExportFormat $f): string => $f->value, $this->formats())));
	}
}
