<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Config\Settings;
use OCP\IUser;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Which confirmation methods apply to an account and a policy, in order
 * (concept section 11.5), and what happens when none does.
 *
 * Adding a method means adding its class to METHODS at its place in the
 * order. A method that fails to load or to answer is left out, so the
 * login falls through to the next method or to the policy.
 */
class ConfirmationPolicy {
	/** @var list<class-string<IConfirmationMethod>> */
	public const METHODS = [
		Methods\SecondFactorMethod::class,
		Methods\EmailCodeMethod::class,
	];

	/** @var list<IConfirmationMethod>|null */
	private ?array $methods = null;

	public function __construct(
		private readonly Settings $settings,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The methods that can confirm the account's login for one policy, in order.
	 *
	 * @return list<IConfirmationMethod>
	 */
	public function methodsFor(IUser $user, StepUpPolicy|string $policy): array {
		$policy = $policy instanceof StepUpPolicy ? $policy : StepUpPolicy::from($policy);
		return $this->methodsForAll($user, [$policy]);
	}

	/**
	 * The methods that can confirm the account's login for every one of the
	 * policies, in order: a method one policy refuses cannot confirm a login
	 * that has that reason too.
	 *
	 * @param list<StepUpPolicy> $policies
	 * @return list<IConfirmationMethod>
	 */
	public function methodsForAll(IUser $user, array $policies): array {
		$available = [];
		foreach ($this->methods() as $method) {
			try {
				foreach ($policies as $policy) {
					if (!$method->isAvailable($user, $policy)) {
						continue 2;
					}
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not check the confirmation method {method}', ['method' => $method->id(), 'exception' => $e]);
				continue;
			}
			$available[] = $method;
		}
		return $available;
	}

	public function method(string $id): ?IConfirmationMethod {
		foreach ($this->methods() as $method) {
			if ($method->id() === $id) {
				return $method;
			}
		}
		return null;
	}

	/**
	 * The configured outcome for a policy when no method is available.
	 */
	public function noMethodOutcome(StepUpPolicy $policy): NoMethodOutcome {
		$value = (string)$this->settings->global($policy->settingKey());
		return NoMethodOutcome::tryFrom($value) ?? $policy->defaultOutcome();
	}

	/**
	 * What happens to a login with these reasons when no method is available:
	 * refused when any policy refuses; otherwise allowed, with every notice
	 * and password change any of them asks for.
	 *
	 * @param list<StepUpPolicy> $policies
	 */
	public function noMethodDecision(array $policies): NoMethodDecision {
		$refuse = false;
		$notify = false;
		$forceChange = false;
		foreach ($policies as $policy) {
			$outcome = $this->noMethodOutcome($policy);
			$refuse = $refuse || $outcome === NoMethodOutcome::Refuse;
			$notify = $notify || $outcome === NoMethodOutcome::AllowNotify;
			$forceChange = $forceChange || $outcome === NoMethodOutcome::AllowForceChange;
		}
		return new NoMethodDecision($refuse, $notify, $forceChange);
	}

	/**
	 * @return list<class-string<IConfirmationMethod>>
	 */
	protected function classes(): array {
		return static::METHODS;
	}

	/**
	 * @return list<IConfirmationMethod>
	 */
	private function methods(): array {
		if ($this->methods === null) {
			$this->methods = [];
			foreach ($this->classes() as $class) {
				try {
					$method = $this->container->get($class);
				} catch (\Throwable $e) {
					$this->logger->error('Intrusion detection could not load the confirmation method {method}', ['method' => $class, 'exception' => $e]);
					continue;
				}
				if ($method instanceof IConfirmationMethod) {
					$this->methods[] = $method;
				}
			}
		}
		return $this->methods;
	}
}
