<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCA\IntrusionDetection\SessionState\Rules\DirectoryScrapingRule;
use OCP\IRequest;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The session-state rules, in order. The first rule that blocks a request
 * decides. Adding a rule means adding its class to RULES.
 *
 * A rule that throws, or cannot be loaded, is logged and treated as letting
 * the request pass: a broken rule must not lock everybody out. The one
 * exception is the step-up rule while a step-up is pending
 * ({@see self::FAIL_CLOSED}): an error must not let an unconfirmed login
 * through.
 *
 * Most requests have nothing for any rule: no session state, no credential
 * the credential check waits to learn about, and no read of the user
 * directory. {@see self::nothingToCheck()} tells so before any rule or its
 * dependencies are built. It knows what each of RULES looks at, so a new
 * rule must be added there too. A pending step-up is session state, so it
 * always reaches the rules.
 */
class SessionStateRules {
	/**
	 * The confirmation of a login comes before everything else: the password
	 * page, for one, must only be reached by a confirmed login.
	 *
	 * @var list<class-string<ISessionStateRule>>
	 */
	public const RULES = [
		Rules\StepUpRule::class,
		Rules\PasswordChangeRule::class,
		Rules\CredentialUseRule::class,
		Rules\LoginHistoryRule::class,
		Rules\LoginNoticeRule::class,
		Rules\DirectoryScrapingRule::class,
	];

	/**
	 * Rules that block on an error while their session marker is set.
	 *
	 * @var array<class-string<ISessionStateRule>, string>
	 */
	public const FAIL_CLOSED = [Rules\StepUpRule::class => SessionState::STEP_UP];

	/** @var list<ISessionStateRule>|null */
	private ?array $rules = null;
	/** @var list<class-string<ISessionStateRule>> rules that could not be loaded */
	private array $missing = [];

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
		private readonly RequestContext $context,
		private readonly IRequest $request,
	) {
	}

	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		if ($this->nothingToCheck($state, fn (): ?string => DirectoryScrapingRule::group($target, $this->request))) {
			return null;
		}
		$rules = $this->rules();
		foreach ($this->missing as $class) {
			if ($this->failsClosed($class, $state)) {
				return Rules\StepUpRule::failed();
			}
		}
		foreach ($rules as $rule) {
			try {
				$block = $rule->check($state, $target);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection session rule {rule} failed', ['rule' => $rule::class, 'exception' => $e]);
				if ($this->failsClosed($rule, $state)) {
					return Rules\StepUpRule::failed();
				}
				continue;
			}
			if ($block !== null) {
				return $block;
			}
		}
		return null;
	}

	/**
	 * The rules for a WebDAV request. Most have nothing to check, and then
	 * neither the request target nor a rule is built.
	 */
	public function checkDav(SessionState $state, string $method, string $uri): ?SessionBlock {
		if ($this->nothingToCheck($state, fn (): ?string => DirectoryRoutes::davGroup(strtoupper($method), $uri, $this->request->getHeader('Depth')))) {
			return null;
		}
		return $this->check($state, RequestTarget::dav($method, $uri));
	}

	/**
	 * @param ISessionStateRule|class-string<ISessionStateRule> $rule
	 */
	private function failsClosed(ISessionStateRule|string $rule, SessionState $state): bool {
		foreach (self::FAIL_CLOSED as $class => $marker) {
			if ($rule instanceof $class || $rule === $class) {
				try {
					return $state->get($marker) !== null;
				} catch (\Throwable) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Whether none of RULES would look at this request: the step-up, password
	 * change, login history and login notice rules need session state, the
	 * credential use rule a credential the guard noted, and the directory
	 * scraping rule a read of the user directory.
	 *
	 * @param \Closure(): ?string $directoryGroup the directory group the request reads
	 */
	private function nothingToCheck(SessionState $state, \Closure $directoryGroup): bool {
		if ($this->classes() !== self::RULES) {
			return false;
		}
		$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
		return $state->isEmpty()
			&& !($use instanceof CredentialUse && $use->needsResolution())
			&& $directoryGroup() === null;
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
					$this->missing[] = $class;
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
