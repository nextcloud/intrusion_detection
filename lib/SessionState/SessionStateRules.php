<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCA\IntrusionDetection\SessionState\Rules\DirectoryScrapingRule;
use OCP\IRequest;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The session-state rules, in order. The first rule that blocks a request
 * decides. Adding a rule means adding its class to RULES and what it looks
 * at to LOOKS_AT.
 *
 * A rule that throws, or cannot be loaded, is logged and treated as letting
 * the request pass: a broken rule must not lock everybody out. The one
 * exception is the step-up rule while a step-up is pending
 * ({@see self::FAIL_CLOSED}, {@see self::onError()}): an error must not let
 * an unconfirmed login through.
 *
 * Most requests have nothing for any rule: none of the markers or request
 * facts in LOOKS_AT. {@see self::nothingToCheck()} tells so before any rule
 * or its dependencies are built, without loading a rule's class. A pending
 * step-up is a session marker, so it always reaches the rules.
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

	/** A credential the credential check waits to learn about ({@see CredentialUseResolver}) */
	public const CREDENTIAL_TO_LEARN = '@credential';
	/** A read of the user directory ({@see DirectoryRoutes}) */
	public const DIRECTORY_READ = '@directory';

	/**
	 * What each rule looks at: session markers, or one of the request facts
	 * above. A rule has nothing to do for a request without any of them.
	 * Kept here rather than on the rules, so that telling this loads no rule.
	 *
	 * @var array<class-string<ISessionStateRule>, list<string>>
	 */
	public const LOOKS_AT = [
		Rules\StepUpRule::class => [SessionMarkers::STEP_UP, SessionMarkers::LOGIN_DETECTIONS, SessionMarkers::CONFIRMATION],
		Rules\PasswordChangeRule::class => [SessionMarkers::PASSWORD_CHANGE],
		Rules\CredentialUseRule::class => [self::CREDENTIAL_TO_LEARN],
		Rules\LoginHistoryRule::class => [SessionMarkers::LOGIN_HISTORY],
		Rules\LoginNoticeRule::class => [SessionMarkers::LOGIN_NOTICE],
		Rules\DirectoryScrapingRule::class => [self::DIRECTORY_READ],
	];

	/** The rule that blocks on an error while a step-up is pending */
	public const FAIL_CLOSED = Rules\StepUpRule::class;

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

	public function check(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		if ($this->nothingToCheck($state, fn (): ?string => DirectoryScrapingRule::group($target, $this->request))) {
			return null;
		}
		$rules = $this->rules();
		if (in_array(self::FAIL_CLOSED, $this->missing, true)) {
			$block = $this->onError($state);
			if ($block !== null) {
				return $block;
			}
		}
		foreach ($rules as $rule) {
			try {
				$block = $rule->check($state, $target);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection session rule {rule} failed', ['rule' => $rule::class, 'exception' => $e]);
				$block = $rule instanceof Rules\StepUpRule ? $this->onError($state) : null;
				if ($block !== null) {
					return $block;
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
	 * The step-up rule alone, for a request no other rule may see yet.
	 * Fails closed like {@see self::check()}.
	 */
	public function checkStepUp(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		try {
			$rule = $this->container->get(self::FAIL_CLOSED);
			return $rule instanceof ISessionStateRule ? $rule->check($state, $target) : $this->onError($state);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection session rule {rule} failed', ['rule' => self::FAIL_CLOSED, 'exception' => $e]);
			return $this->onError($state);
		}
	}

	/**
	 * The rules for a WebDAV request. Most have nothing to check, and then
	 * neither the request target nor a rule is built.
	 */
	public function checkDav(SessionMarkers $state, string $method, string $uri): ?SessionBlock {
		if ($this->nothingToCheck($state, fn (): ?string => DirectoryRoutes::davGroup(strtoupper($method), $uri, $this->request->getHeader('Depth')))) {
			return null;
		}
		return $this->check($state, RequestTarget::dav($method, $uri));
	}

	/**
	 * The answer when checking failed: blocked while a step-up marker is
	 * readable and present, so that an error never lets an unconfirmed login
	 * through; otherwise the request passes.
	 */
	public function onError(SessionMarkers $state): ?SessionBlock {
		try {
			return $state->get(SessionMarkers::STEP_UP) === null ? null : Rules\StepUpRule::failed();
		} catch (\Throwable) {
			return null;
		}
	}

	/**
	 * Whether none of RULES looks at anything this request has ({@see self::LOOKS_AT}).
	 *
	 * @param \Closure(): ?string $directoryGroup the directory group the request reads
	 */
	private function nothingToCheck(SessionMarkers $state, \Closure $directoryGroup): bool {
		if ($this->classes() !== self::RULES) {
			return false;
		}
		$markers = $state->all();
		foreach (self::LOOKS_AT as $facts) {
			foreach ($facts as $fact) {
				$present = match ($fact) {
					self::CREDENTIAL_TO_LEARN => $this->credentialToLearn(),
					self::DIRECTORY_READ => $directoryGroup() !== null,
					default => isset($markers[$fact]),
				};
				if ($present) {
					return false;
				}
			}
		}
		return true;
	}

	private function credentialToLearn(): bool {
		$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
		return $use instanceof CredentialUse && $use->needsResolution();
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
