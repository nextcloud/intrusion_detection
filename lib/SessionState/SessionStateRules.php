<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The session-state rules, in order. The first rule that blocks a request
 * decides. Adding a rule means adding its class to RULES.
 *
 * A rule that throws is logged and treated as letting the request pass: a
 * broken rule must not lock everybody out.
 */
class SessionStateRules {
	/** @var list<class-string<ISessionStateRule>> */
	public const RULES = [
		Rules\PasswordChangeRule::class,
	];

	/** @var list<ISessionStateRule>|null */
	private ?array $rules = null;

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		foreach ($this->rules() as $rule) {
			try {
				$block = $rule->check($state, $target);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection session rule {rule} failed', ['rule' => $rule::class, 'exception' => $e]);
				continue;
			}
			if ($block !== null) {
				return $block;
			}
		}
		return null;
	}

	/**
	 * @return list<class-string<ISessionStateRule>>
	 */
	protected function classes(): array {
		return self::RULES;
	}

	/**
	 * @return list<ISessionStateRule>
	 */
	private function rules(): array {
		if ($this->rules === null) {
			$this->rules = [];
			foreach ($this->classes() as $class) {
				try {
					$rule = $this->container->get($class);
				} catch (\Throwable $e) {
					$this->logger->error('Intrusion detection could not load the session rule {rule}', ['rule' => $class, 'exception' => $e]);
					continue;
				}
				if ($rule instanceof ISessionStateRule) {
					$this->rules[] = $rule;
				}
			}
		}
		return $this->rules;
	}
}
