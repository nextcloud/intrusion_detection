<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Notification\DigestSender;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;
use Psr\Log\LoggerInterface;

/**
 * Hourly: sends the admin digest when it is due (concept section 11.10).
 */
class DigestJob extends TimedJob {
	public function __construct(
		ITimeFactory $time,
		private readonly DigestSender $sender,
		private readonly LoggerInterface $logger,
	) {
		parent::__construct($time);
		$this->setInterval(3600);
	}

	#[\Override]
	protected function run(mixed $argument): void {
		$result = $this->sender->sendIfDue();
		$this->logger->debug('Intrusion detection digest: {result}', ['result' => $result]);
	}
}
