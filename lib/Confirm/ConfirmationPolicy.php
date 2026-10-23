<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Config\AppSettings;
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
 *
 * An administrator ({@see Administrators}) never confirms with an email
 * code while the second factor or an approval can confirm the login: a
 * mailbox is weaker than either. Only an administrator without both gets
 * the code.
 */
class ConfirmationPolicy {
	/** @var list<class-string<IConfirmationMethod>> */
	public const METHODS = [
		Methods\SecondFactorMethod::class,
		Methods\KnownDeviceMethod::class,
		Methods\EmailCodeMethod::class,
		Methods\AdminApprovalMethod::class,
	];

	/** @var list<IConfirmationMethod>|null */
	private ?array $methods = null;

	public function __construct(
		private readonly AppSettings $settings,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
		private readonly Administrators $administrators,
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
		return $this->withoutEmailForAdministrators($user, $available);
	}

	/**
	 * Whether the account could confirm a login with all these policies at
	 * the login form, from any of its browsers
	 * ({@see IConfirmationMethod::isAvailableInBrowser()}).
	 *
	 * @param list<StepUpPolicy> $policies
	 */
	public function canConfirmInBrowser(IUser $user, array $policies): bool {
		foreach ($this->methods() as $method) {
			try {
				foreach ($policies as $policy) {
					if (!$method->isAvailableInBrowser($user, $policy)) {
						continue 2;
					}
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not check the confirmation method {method}', ['method' => $method->id(), 'exception' => $e]);
				continue;
			}
			return true;
		}
		return false;
	}

	/**
	 * The method a pending login offers, while it can still confirm every
	 * reason of that login; null otherwise.
	 */
	public function offered(IUser $user, StepUpState $stepUp, string $id): ?IConfirmationMethod {
		if (!$stepUp->hasMethod($id)) {
			return null;
		}
		$method = $this->method($id);
		if ($method === null) {
			return null;
		}
		foreach ($stepUp->policies as $policy) {
			$known = StepUpPolicy::tryFrom($policy);
			if ($known === null || !$method->isAvailable($user, $known)) {
				return null;
			}
		}
		return $method;
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
		$value = $this->settings->stepUpNoMethod($policy->value);
		return NoMethodOutcome::tryFrom($value) ?? $policy->defaultOutcome();
	}

	/**
	 * What happens to a login with these reasons when no method is available:
	 * refused when any policy refuses; otherwise allowed, with every notice
	 * and password change any of them asks for.
	 *
	 * A reason that a familiar place softens ({@see StepUpPolicy::familiarPlaceSoftensRefusal()})
	 * never refuses there: that login is allowed with a notice instead.
	 * `$familiar` is asked only when it decides.
	 *
	 * @param list<StepUpPolicy> $policies
	 * @param ?\Closure(): bool $familiar
	 */
	public function noMethodDecision(array $policies, ?\Closure $familiar = null): NoMethodDecision {
		$refuse = false;
		$notify = false;
		$forceChange = false;
		foreach ($policies as $policy) {
			$outcome = $this->noMethodOutcome($policy);
			if ($outcome === NoMethodOutcome::Refuse && $policy->familiarPlaceSoftensRefusal() && $familiar !== null && $familiar()) {
				$outcome = NoMethodOutcome::AllowNotify;
			}
			$refuse = $refuse || $outcome === NoMethodOutcome::Refuse;
			$notify = $notify || $outcome === NoMethodOutcome::AllowNotify;
			$forceChange = $forceChange || $outcome === NoMethodOutcome::AllowForceChange;
		}
		return new NoMethodDecision($refuse, $notify, $forceChange);
	}

	/**
	 * The methods without the email code when the account is an
	 * administrator and the second factor or an approval is among them.
	 * When it cannot be told whether the account is an administrator, the
	 * stronger methods are kept alone.
	 *
	 * @param list<IConfirmationMethod> $methods
	 * @return list<IConfirmationMethod>
	 */
	private function withoutEmailForAdministrators(IUser $user, array $methods): array {
		$ids = array_map(static fn (IConfirmationMethod $method): string => $method->id(), $methods);
		if (!in_array(IConfirmationMethod::EMAIL_CODE, $ids, true)
			|| array_intersect([IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::ADMIN_APPROVAL], $ids) === []) {
			return $methods;
		}
		try {
			if (!$this->administrators->isAdministrator($user)) {
				return $methods;
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not tell whether an account is an administrator', ['exception' => $e]);
		}
		return array_values(array_filter($methods, static fn (IConfirmationMethod $method): bool => $method->id() !== IConfirmationMethod::EMAIL_CODE));
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
