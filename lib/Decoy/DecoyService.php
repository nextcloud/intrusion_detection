<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Decoy;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Decoy\Db\Decoy;
use OCA\IntrusionDetection\Decoy\Db\DecoyMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Traps\AccountNames;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ISecureRandom;

/**
 * Decoy credentials: fake app passwords or tokens an administrator plants
 * where only an intruder would find them.
 *
 * The secret is generated here, returned once and never stored: the table
 * holds a keyed fingerprint of it (the key derives from the instance secret
 * in config.php). An optional login name is a weaker trap of its own; it
 * may never be an existing account.
 */
class DecoyService {
	public const MAX_LABEL = 200;
	/** The longest login name */
	public const MAX_LOGIN_NAME = 64;
	public const LOGIN_NAME_PATTERN = '/^[^\s\x00-\x1f\x7f]{1,' . self::MAX_LOGIN_NAME . '}$/u';

	public function __construct(
		private readonly DecoyMapper $mapper,
		private readonly Fingerprinter $fingerprinter,
		private readonly ISecureRandom $random,
		private readonly AccountNames $accounts,
		private readonly AuditLogger $audit,
		private readonly ITimeFactory $timeFactory,
		private readonly TrapNameCollisions $collisions,
		private readonly HotState $hotState,
	) {
	}

	/**
	 * @return array{0: Decoy, 1: string} the stored decoy and its secret, which is never available again
	 * @throws InvalidParamException for an empty or too long label, or an invalid or existing login name
	 */
	public function create(string $label, #[\SensitiveParameter] ?string $loginName, DecoyFormat $format, string $actor): array {
		$label = trim((string)preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $label));
		if ($label === '' || mb_strlen($label) > self::MAX_LABEL) {
			throw new InvalidParamException('invalid_item', ['param' => 'label', 'item' => mb_substr($label, 0, 40)]);
		}
		$loginName = $loginName === null ? null : AccountNames::normalise($loginName);
		if ($loginName === '') {
			$loginName = null;
		}
		if ($loginName !== null) {
			if (preg_match(self::LOGIN_NAME_PATTERN, $loginName) !== 1) {
				throw new InvalidParamException('invalid_item', ['param' => 'login_name', 'item' => mb_substr($loginName, 0, 40)]);
			}
			if ($this->accounts->exists($loginName)) {
				throw new InvalidParamException('existing_user', ['param' => 'login_name', 'item' => $loginName]);
			}
		}

		do {
			$secret = $format->generate($this->random);
			$secretHmac = bin2hex($this->fingerprinter->decoy($secret));
		} while ($this->mapper->secretExists($secretHmac));

		$decoy = new Decoy();
		$decoy->setLabel($label);
		$decoy->setLoginName($loginName);
		$decoy->setSecretHmac($secretHmac);
		$decoy->setFormat($format->value);
		$decoy->setCreatedBy(mb_substr($actor, 0, 64));
		$decoy->setTriggerCount(0);
		$decoy = $this->mapper->insert($decoy);
		$this->updateCount();
		$this->audit->log('decoy credential %s ("%s") created by %s', ['id' => (string)$decoy->getId(), 'label' => $label, 'actor' => $actor]);
		return [$decoy, $secret];
	}

	/**
	 * @throws DoesNotExistException
	 */
	public function delete(string $id, string $actor): Decoy {
		$decoy = $this->mapper->findById($id);
		$this->mapper->delete($decoy);
		$this->updateCount();
		$this->audit->log('decoy credential %s ("%s") deleted by %s', ['id' => $id, 'label' => $decoy->getLabel(), 'actor' => $actor]);
		return $decoy;
	}

	/**
	 * How many decoys were created before a time, such as a change of the
	 * instance secret, after which their secret no longer matches.
	 */
	public function countCreatedBefore(int $before): int {
		return $before <= 0 ? 0 : $this->mapper->countCreatedBefore($before);
	}

	/**
	 * @return list<Decoy>
	 */
	public function list(): array {
		return $this->mapper->findAll();
	}

	/**
	 * The decoy a failed login used, if any, and whether it used the secret
	 * (a sure sign) or only the decoy's login name (a weaker one). The login
	 * name of a decoy that has become an account in the meantime is skipped.
	 * Costs nothing while no decoy exists.
	 *
	 * @return ?array{0: Decoy, 1: bool}
	 */
	public function match(#[\SensitiveParameter] ?string $password, #[\SensitiveParameter] string $loginName): ?array {
		if ($this->hotState->decoyCount() === 0) {
			return null;
		}
		$secretHmac = $password === null || $password === '' ? null : bin2hex($this->fingerprinter->decoy($password));
		$name = AccountNames::normalise($loginName);
		$name = $name === '' || mb_strlen($name) > 64 ? null : $name;
		$byName = null;
		foreach ($this->mapper->findMatching($secretHmac, $name) as $decoy) {
			if ($secretHmac !== null && hash_equals($decoy->getSecretHmac(), $secretHmac)) {
				return [$decoy, true];
			}
			$byName ??= $decoy;
		}
		if ($byName === null || $this->accounts->exists((string)$name)) {
			return null;
		}
		return [$byName, false];
	}

	public function triggered(Decoy $decoy): void {
		$this->mapper->markTriggered((string)$decoy->getId(), $this->timeFactory->getTime());
	}

	/**
	 * Decoy login names that have become accounts since the decoy was made.
	 *
	 * @return list<string>
	 */
	public function loginNameCollisions(): array {
		return array_values(array_filter($this->mapper->loginNames(), fn (string $name): bool => $this->accounts->exists($name)));
	}

	private function updateCount(): void {
		$this->hotState->setDecoyCount($this->mapper->countAll());
		$this->collisions->refresh();
	}
}
