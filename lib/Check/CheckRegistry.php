<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Signal\AdminChanged;
use OCA\IntrusionDetection\Signal\BlockHeldBack;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\InteractivePasswordLogin;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\LoginFlowGranted;
use OCA\IntrusionDetection\Signal\ResetRequested;
use OCA\IntrusionDetection\Signal\SecondFactorFailure;
use OCA\IntrusionDetection\Signal\SecurityChanged;
use OCA\IntrusionDetection\Signal\ShareAccessFailed;
use OCA\IntrusionDetection\Signal\SuccessfulLogin;
use Psr\Container\ContainerInterface;

/**
 * All checks the app knows, and the detectors of each signal. Adding a check
 * means adding its class to CHECKS, and its detector to DETECTORS.
 */
class CheckRegistry {
	/** @var list<class-string<ICheck>> */
	public const CHECKS = [
		Checks\ManualBlock\ManualBlock::class,
		Checks\SharedAddress\SharedAddress::class,
		Checks\BlocklistMatch\BlocklistMatch::class,
		Checks\CredentialStuffing\CredentialStuffing::class,
		Checks\PasswordSpraying\PasswordSpraying::class,
		Checks\AccountUnderAttack\AccountUnderAttack::class,
		Checks\ReservedName\ReservedName::class,
		Checks\TrapUrl\TrapUrl::class,
		Checks\DecoyCredential\DecoyCredential::class,
		Checks\InjectionProbe\InjectionProbe::class,
		Checks\ShareBruteforce\ShareBruteforce::class,
		Checks\ResetProbing\ResetProbing::class,
		Checks\LoginFlowMismatch\LoginFlowMismatch::class,
		Checks\BreachedPassword\BreachedPassword::class,
		Checks\SecondFactorFailed\SecondFactorFailed::class,
		Checks\AdminChange\AdminChange::class,
		Checks\TokenConcurrentUse\TokenConcurrentUse::class,
		Checks\NewLogin\NewLogin::class,
		Checks\StepUpFailed\StepUpFailed::class,
		Checks\StepUpRefused\StepUpRefused::class,
		Checks\StepUpRefusedClient\StepUpRefusedClient::class,
		Checks\StepUpUnconfirmed\StepUpUnconfirmed::class,
		Checks\UserDenied\UserDenied::class,
		Checks\RiskyNetwork\RiskyNetwork::class,
		Checks\DirectoryScraping\DirectoryScraping::class,
		Checks\AccountTakeover\AccountTakeover::class,
		Checks\AccountLocked\AccountLocked::class,
	];

	/**
	 * The detectors of each signal, by the id of their check, in the order
	 * they run ({@see \OCA\IntrusionDetection\Signal\SignalDispatcher}). The
	 * ids are spelled out so that a signal whose checks are off loads no
	 * check and no detector. A decoy and a reserved name answer a failed login
	 * on their own, so nothing after them runs; a listed address is recorded
	 * whatever else the login was.
	 *
	 * @var array<class-string<ISignal>, array<string, class-string<IDetector>>>
	 */
	public const DETECTORS = [
		FailedLogin::class => [
			'blocklist_match' => Checks\BlocklistMatch\BlocklistMatchDetector::class,
			'decoy_credential' => Checks\DecoyCredential\DecoyCredentialDetector::class,
			'reserved_name' => Checks\ReservedName\ReservedNameDetector::class,
		],
		FailedLoginAttempt::class => [
			'password_spraying' => Checks\PasswordSpraying\PasswordSprayingDetector::class,
			'credential_stuffing' => Checks\CredentialStuffing\CredentialStuffingDetector::class,
			'account_under_attack' => Checks\AccountUnderAttack\AccountUnderAttackDetector::class,
		],
		SuccessfulLogin::class => [
			'password_spraying' => Checks\PasswordSpraying\PasswordSprayingDetector::class,
			'risky_network' => Checks\RiskyNetwork\RiskyNetworkDetector::class,
		],
		InteractivePasswordLogin::class => [
			'breached_password' => Checks\BreachedPassword\BreachedPasswordDetector::class,
		],
		Checks\TokenConcurrentUse\CredentialSwitched::class => [
			'token_concurrent_use' => Checks\TokenConcurrentUse\TokenConcurrentUseDetector::class,
		],
		Checks\NewLogin\UnfamiliarLogin::class => [
			'new_login' => Checks\NewLogin\NewLoginDetector::class,
		],
		SecondFactorFailure::class => [
			'second_factor_failed' => Checks\SecondFactorFailed\SecondFactorFailedDetector::class,
		],
		SecurityChanged::class => [
			'account_takeover' => Checks\AccountTakeover\AccountTakeoverDetector::class,
		],
		ShareAccessFailed::class => [
			'share_bruteforce' => Checks\ShareBruteforce\ShareBruteforceDetector::class,
		],
		ResetRequested::class => [
			'reset_probing' => Checks\ResetProbing\ResetProbingDetector::class,
		],
		LoginFlowGranted::class => [
			'login_flow_mismatch' => Checks\LoginFlowMismatch\LoginFlowMismatchDetector::class,
		],
		AdminChanged::class => [
			'admin_change' => Checks\AdminChange\AdminChangeDetector::class,
		],
		BlockHeldBack::class => [
			'shared_address' => Checks\SharedAddress\SharedAddressDetector::class,
		],
	];

	/** @var array<string, CheckDefinition>|null */
	private ?array $definitions = null;
	/** @var array<string, class-string<ICheck>> */
	private array $classes = [];

	public function __construct(
		private readonly ContainerInterface $container,
	) {
	}

	/**
	 * @return array<string, CheckDefinition> keyed by check id, in CHECKS order
	 */
	public function all(): array {
		if ($this->definitions === null) {
			$this->definitions = [];
			foreach (self::CHECKS as $class) {
				$definition = $this->instance($class)->definition();
				if (isset($this->definitions[$definition->id])) {
					throw new \LogicException('Duplicate check id ' . $definition->id);
				}
				$this->definitions[$definition->id] = $definition;
				$this->classes[$definition->id] = $class;
			}
		}
		return $this->definitions;
	}

	public function has(string $id): bool {
		return isset($this->all()[$id]);
	}

	/**
	 * @throws InvalidParamException
	 */
	public function get(string $id): CheckDefinition {
		return $this->all()[$id] ?? throw new InvalidParamException('unknown_check', ['check' => $id]);
	}

	/**
	 * The definition of a check, or null for an id no check has.
	 */
	public function find(string $id): ?CheckDefinition {
		return $this->all()[$id] ?? null;
	}

	/**
	 * The check object, for callers that run its detector.
	 *
	 * @template T of ICheck
	 * @param class-string<T> $class
	 * @return T
	 */
	public function check(string $class): ICheck {
		return $this->instance($class);
	}

	/**
	 * @return class-string<ICheck>
	 */
	public function classOf(string $id): string {
		$this->all();
		return $this->classes[$id] ?? throw new InvalidParamException('unknown_check', ['check' => $id]);
	}

	/**
	 * @return array<string, CheckDefinition> the checks an admin configures (internal ones excluded)
	 */
	public function configurable(): array {
		return array_filter($this->all(), static fn (CheckDefinition $d): bool => !$d->internal);
	}

	/**
	 * @template T of ICheck
	 * @param class-string<T> $class
	 * @return T
	 */
	private function instance(string $class): ICheck {
		$check = $this->container->get($class);
		if (!$check instanceof $class) {
			throw new \LogicException($class . ' is not a check');
		}
		return $check;
	}
}
