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
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ISecureRandom;
use Psr\Log\LoggerInterface;

/**
 * Writes the active blocks for firewalls and fail2ban into the export
 * directory ({@see ExportDirectory}). The app never runs a firewall command
 * itself; root-owned loaders pick the files up ({@see FirewallSnippets}).
 *
 * - `bans.txt`, `bans.nft`, `bans.ipset` are rewritten from the active blocks
 *   by the background job ({@see \OCA\IntrusionDetection\BackgroundJob\FirewallExportJob}),
 *   at its next run after a block was created, raised or lifted, after the
 *   first block ended that was in the files, or after the directory, the
 *   formats, the protection switch or the protected ranges changed. One
 *   cheap query tells whether the blocks did; a block ending alone does not
 *   change it, the time of the first one to end is kept with the files.
 *   Firewalls drop ended blocks by themselves (each entry carries its
 *   timeout), so with many blocks ending all the time the files are still
 *   written at most once per run of the job. Writing them takes a while
 *   with many blocks, so it never happens in the request that blocked an
 *   address. Each file is written to a new temporary file and renamed into
 *   place, so a reader never sees half a file.
 * - `bans.log` is appended to at once, one line per block and lift, and
 *   rotated to `bans.log.1` at 10 MB.
 * - The files never block loopback, the server itself or the brute-force
 *   allowlist ({@see ProtectedRanges}), and are empty while protection is off.
 *   With more than MAX_ENTRIES blocks, those that last longest are kept.
 *
 * Nothing is written while `intrusion_detection.export_dir` is unset or no
 * format is switched on. Failures are recorded for the admin page, never thrown
 * at the request that changed a block.
 */
class FirewallExporter {
	/** The ids_state row of the last write */
	public const STATE = 'firewall_export';
	public const LOG_ROTATE_BYTES = 10 * 1024 * 1024;
	/** At most this many blocks are exported */
	public const MAX_ENTRIES = 50000;
	private const FILE_MODE = 0o640;

	public function __construct(
		private readonly ExportDirectory $directory,
		private readonly Settings $settings,
		private readonly BanMapper $bans,
		private readonly AppState $state,
		private readonly ProtectedRanges $protected,
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
		$state = $this->state->getJson(self::STATE);
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
	 * A block was created, raised or lifted: log it. The other files follow
	 * at the next run of the background job. Never throws.
	 */
	public function banChanged(Ban $ban, bool $lifted): void {
		if (!$this->isActive() || !$this->settings->isEnabled() || !in_array(ExportFormat::Log, $this->formats(), true)) {
			return;
		}
		$now = $this->timeFactory->getTime();
		try {
			$this->appendLog($this->directory->resolve(), $lifted ? ExportRenderer::liftLine($ban, $now) : ExportRenderer::banLine($ban, $now));
		} catch (ExportException $e) {
			$this->recordError($e->reason, $now);
		}
	}

	/**
	 * Rewrite the snapshot files now.
	 *
	 * @throws ExportException when the directory cannot be used or a file cannot be written
	 */
	public function write(): ExportStatus {
		$now = $this->timeFactory->getTime();
		try {
			$dir = $this->directory->resolve();
			$changes = $this->bans->changeSignature($now);
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
		$this->state->setJson(self::STATE, [
			'last_write_at' => $now,
			'error' => null,
			'error_at' => null,
			'entries' => count($entries),
			'next_expiry' => self::nextChange($entries, $now),
			'signature' => $this->signature(),
			'bans' => $changes,
		]);
		return $this->status();
	}

	/**
	 * For the background job: rewrite only when a block was created, raised
	 * or lifted, the first block in the files ended (or an ipset timeout ran
	 * out), or the directory, the formats, the protection switch or the
	 * protected ranges changed. Otherwise one aggregate query is all it
	 * costs.
	 *
	 * @return bool whether the files were written
	 */
	public function writeIfDue(): bool {
		if (!$this->isActive()) {
			return false;
		}
		$state = $this->state->getJson(self::STATE);
		$lastWrite = $state['last_write_at'] ?? null;
		$nextExpiry = is_int($state['next_expiry'] ?? null) ? $state['next_expiry'] : 0;
		$now = $this->timeFactory->getTime();
		$due = !is_int($lastWrite)
			|| ($state['signature'] ?? null) !== $this->signature()
			|| ($nextExpiry > 0 && $now >= $nextExpiry)
			|| ($state['bans'] ?? null) !== $this->bans->changeSignature($lastWrite);
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
	 * The blocks to write: none while protection is off; the longest-lasting
	 * MAX_ENTRIES otherwise, sorted, without overlaps and with the protected
	 * ranges cut out.
	 *
	 * @return list<ExportEntry>
	 */
	private function entries(int $now): array {
		if (!$this->settings->isEnabled()) {
			return [];
		}
		$entries = [];
		foreach ($this->bans->findActiveForExport($now, self::MAX_ENTRIES) as $row) {
			try {
				$entries[] = ExportEntry::fromRow($row);
			} catch (\InvalidArgumentException) {
				$this->logger->warning('Intrusion detection skipped a block with an invalid range in the firewall export', ['reference' => $row['reference']]);
			}
		}
		return ExportEntry::disjoint(ExportEntry::sort($entries), $this->protected->ranges());
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
		$state = $this->state->getJson(self::STATE);
		if (($state['error'] ?? null) === $reason) {
			return;
		}
		$state['error'] = $reason;
		$state['error_at'] = $now;
		$this->state->setJson(self::STATE, $state);
		$this->logger->warning('Intrusion detection could not write the firewall export: {reason}', ['reason' => $reason]);
	}

	/**
	 * Changes when the directory, the formats, the protection switch or the
	 * protected ranges (the allowlist, the server's addresses) change, so the
	 * job rewrites then.
	 */
	private function signature(): string {
		return hash('sha256', ($this->directory->configured() ?? '') . "\0" . implode(',', array_map(static fn (ExportFormat $f): string => $f->value, $this->formats()))
			. "\0" . ($this->settings->isEnabled() ? 'on' : 'off')
			. "\0" . json_encode($this->protected->ranges()));
	}
}
