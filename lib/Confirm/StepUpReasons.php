<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Login\LoginContext;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The reasons why a password login needs extra confirmation, in order.
 * Adding a reason means adding its provider to PROVIDERS, and its policy's
 * default outcome without a method to
 * {@see \OCA\IntrusionDetection\Config\GlobalSettings::STEP_UP_NO_METHOD_DEFAULTS}.
 *
 * A provider that fails is logged and treated as not applying: a broken
 * reason must not lock everybody out. The one exception is an explicit
 * rule ({@see StepUpPolicy::isExplicitRule()}): it applies when it cannot
 * be evaluated, so that an error never lets a login around it.
 */
class StepUpReasons {
	/** @var list<class-string<IStepUpReason>> */
	public const PROVIDERS = [
		Reasons\FlaggedSourceReason::class,
		Reasons\SprayedPasswordReason::class,
		Reasons\ProtectedAccountReason::class,
		Reasons\BreachedPasswordReason::class,
		Reasons\RiskyNetworkReason::class,
		Reasons\RiskHighReason::class,
		Reasons\AdminOutsideNetworksReason::class,
	];

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The policies that have a provider, in provider order.
	 *
	 * @return list<StepUpPolicy>
	 */
	public static function policies(): array {
		$policies = [];
		foreach (static::PROVIDERS as $class) {
			$policy = $class::policy();
			if (!in_array($policy, $policies, true)) {
				$policies[] = $policy;
			}
		}
		return $policies;
	}

	/**
	 * The policies of every reason that applies to the login.
	 *
	 * @param bool $explicitOnly only the explicit rules, as on the brute-force allowlist
	 * @return list<StepUpPolicy>
	 */
	public function collect(LoginContext $login, bool $explicitOnly = false): array {
		$policies = [];
		foreach ($this->providers() as $class) {
			$policy = $class::policy();
			if (in_array($policy, $policies, true) || ($explicitOnly && !$policy->isExplicitRule())) {
				continue;
			}
			try {
				$provider = $this->container->get($class);
				if ($provider instanceof IStepUpReason && $provider->applies($login)) {
					$policies[] = $policy;
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not evaluate the step-up reason {reason}', ['reason' => $policy->value, 'exception' => $e]);
				if ($policy->isExplicitRule()) {
					$policies[] = $policy;
				}
			}
		}
		return $policies;
	}

	/**
	 * @return list<class-string<IStepUpReason>>
	 */
	protected function providers(): array {
		return static::PROVIDERS;
	}
}
