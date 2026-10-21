<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Whether the login of a session was risky (concept section 10.14): it
 * had a reason for a confirmation that no second factor or email code
 * satisfied, it came from an unknown device with a raised risk score, or
 * from a risky network. Each kind of evidence is a signal in SIGNALS; the
 * earliest risky login any signal reports wins, since the takeover window
 * starts there.
 *
 * A signal that fails is logged and ignored.
 */
class RiskyLogins {
	/** @var list<class-string<IRiskyLoginSignal>> */
	public const SIGNALS = [
		Signals\UnconfirmedLoginSignal::class,
		Signals\UnknownDeviceSignal::class,
		Signals\RiskyNetworkSignal::class,
	];

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	public function of(string $uid, ?int $sessionTokenId): ?RiskyLogin {
		$found = null;
		foreach ($this->signals() as $class) {
			try {
				$signal = $this->container->get($class);
				$login = $signal instanceof IRiskyLoginSignal ? $signal->riskyLogin($uid, $sessionTokenId) : null;
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not read the risky login signal {signal}', ['signal' => $class, 'exception' => $e]);
				continue;
			}
			if ($login !== null && ($found === null || $login->at < $found->at)) {
				$found = $login;
			}
		}
		return $found;
	}

	/**
	 * @return list<class-string<IRiskyLoginSignal>>
	 */
	protected function signals(): array {
		return self::SIGNALS;
	}
}
