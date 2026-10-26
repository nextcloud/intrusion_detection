<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Dav\RemoteSessionCheck;
use OCA\IntrusionDetection\Listener\Login\ILoginStep;
use OCA\IntrusionDetection\Listener\Login\LoginFacts;
use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\State\HotState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The app's one listener for successful logins. It works out what is
 * known about the login once ({@see LoginFacts}) and runs the login steps
 * in the order of STEPS; each step says whether it applies, and one that
 * does not is not built.
 *
 * Core reports a login for every request with Basic or Bearer
 * credentials. For an app that sends its credential again, the
 * {@see LoginGate} is asked once: after the app's first request of the
 * hour from an address, nothing that records logins is built.
 *
 * Failures are logged per step and never break the login. The one
 * exception is a login with a step-up on a remote.php request that the
 * app's WebDAV plugins do not guard: it is refused there
 * ({@see RemoteSessionCheck::atLogin()}). What depends on the request is
 * looked up per login: core keeps its listeners for the whole process.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent>
 */
class LoginListener implements IEventListener {
	public const PRIORITY = Application::LOGIN_PRIORITY;

	/**
	 * The step-up comes first, so that a new password it requires is
	 * picked up by the password change at once; the known device comes
	 * before the history and the notice, which use it.
	 *
	 * @var list<class-string<ILoginStep>>
	 */
	public const STEPS = [
		Login\StepUpStep::class,
		Login\AdminSessionStep::class,
		Login\RecordStep::class,
		Login\PayloadStep::class,
		Login\BreachStep::class,
		Login\PasswordChangeStep::class,
		Login\CredentialUseStep::class,
		Login\KnownDeviceStep::class,
		Login\NewLoginStep::class,
		Login\HistoryStep::class,
		Login\NoticeStep::class,
	];

	public function __construct(
		private readonly AppSettings $settings,
		private readonly HotState $hotState,
		private readonly RequestContext $context,
		private readonly LoginGate $gate,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserLoggedInEvent && !$event instanceof UserLoggedInWithCookieEvent) {
			return;
		}
		try {
			if (!$this->settings->isEnabled()) {
				return;
			}
			$facts = $this->facts($event);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not handle a login', ['exception' => $e]);
			return;
		}
		foreach ($this->steps() as $class) {
			try {
				if (!$class::appliesTo($facts)) {
					continue;
				}
				$step = $this->container->get($class);
				if ($step instanceof ILoginStep) {
					$step->handle($facts);
				}
			} catch (\Throwable $e) {
				// One step that fails must not stop the others, nor the login.
				$this->logger->error('Intrusion detection could not run {step} at a login', ['step' => $class, 'exception' => $e]);
			}
		}
		if ($facts->confirmation?->stepUp !== null) {
			$request = $this->container->get(IRequest::class);
			if ($request instanceof IRequest) {
				RemoteSessionCheck::atLogin($request, $this->context, $facts->confirmation);
			}
		}
	}

	/**
	 * @return list<class-string<ILoginStep>>
	 */
	protected function steps(): array {
		return self::STEPS;
	}

	private function facts(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): LoginFacts {
		$addresses = $this->container->get(RemoteAddressResolver::class);
		$classifier = $this->container->get(LoginClassifier::class);
		$request = $this->container->get(IRequest::class);
		if (!$addresses instanceof RemoteAddressResolver || !$classifier instanceof LoginClassifier || !$request instanceof IRequest) {
			throw new \LogicException('The login services are missing');
		}
		$user = $event->getUser();
		$source = $addresses->current();
		$now = $this->timeFactory->getTime();
		return new LoginFacts(
			$event,
			$classifier->classify($event),
			$user,
			$source,
			$request->getHeader('User-Agent'),
			$this->context,
			fn (): ?bool => $source === null ? null : $this->gate->isFirst($user->getUID(), $source->ipKey, $now),
			static fn (): bool => $source !== null && $addresses->isBypassListed($source),
			fn (): bool => UnconfirmedSessions::mayExistIn($this->hotState, $now),
		);
	}
}
