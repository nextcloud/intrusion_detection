<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use Psr\Container\ContainerInterface;

/**
 * All checks the app knows. Adding a check means adding its class to CHECKS.
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
