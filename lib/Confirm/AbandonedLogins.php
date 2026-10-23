<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Db\IPurges;
use Psr\Log\LoggerInterface;

/**
 * Ends logins that were left waiting for their confirmation: the browser
 * was closed, nobody came back. The step-up rule ends a pending login on
 * its next request; without one, the login would never end and the user
 * would never be told. A background job ends it at its deadline, as the
 * rule would ({@see LoginConfirmations::abandoned()}): `step_up_failed`
 * with the timeout rule (never a block),
 * which ends its session and tells the user, and the login history says
 * it failed.
 *
 * The session's row stays, without its deadline, so that the session
 * cannot come back unconfirmed.
 *
 * While protection is off, a login past its deadline is dropped silently:
 * it ends the same way, but without a detection or a notice, so that
 * turning protection back on does not tell users days later.
 */
class AbandonedLogins implements IPurges {
	/** Logins ended per run */
	public const BATCH = 200;

	public function __construct(
		private readonly StepUpSessionMapper $sessions,
		private readonly LoginConfirmations $confirmations,
		private readonly AppSettings $appSettings,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * End the logins left waiting past their deadline.
	 *
	 * @return int the logins ended, with or without a notice
	 */
	#[\Override]
	public function purge(int $now): int {
		$enabled = $this->appSettings->isEnabled();
		$ended = 0;
		foreach ($this->sessions->findAbandoned($now, self::BATCH) as $row) {
			if (!$this->sessions->endWaiting($row['session_key'])) {
				continue;
			}
			try {
				$stepUp = new StepUpState($row['uid'], ConfirmationStatus::Pending, $row['policies'], $row['created_at'], $row['deadline'], $row['ip']);
				$this->confirmations->abandoned($stepUp, $enabled);
				$ended++;
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not end a login that waited for its confirmation', ['exception' => $e]);
			}
		}
		return $ended;
	}
}
