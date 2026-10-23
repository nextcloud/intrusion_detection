<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Listener\Login\ILoginStep;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The app's login listener, running only the given steps, built by the test.
 */
final class LoginSteps {
	/**
	 * @param array<class-string<ILoginStep>, ILoginStep> $steps
	 */
	public static function listener(
		array $steps,
		AppSettings $settings,
		IRequest $request,
		?RequestContext $context = null,
		?RemoteAddressResolver $addresses = null,
		?LoginGate $gate = null,
		?LoggerInterface $logger = null,
		?HotState $hotState = null,
	): LoginListener {
		$context ??= new RequestContext();
		$services = $steps + [
			RemoteAddressResolver::class => $addresses ?? new RemoteAddressResolver($request, Server::get(IThrottler::class), Server::get(ServerAddresses::class)),
			LoginClassifier::class => new LoginClassifier($request, $context),
			IRequest::class => $request,
		];
		$container = new class($services) implements ContainerInterface {
			/** @param array<string, object> $services */
			public function __construct(
				private readonly array $services,
			) {
			}

			public function get(string $id): mixed {
				return $this->services[$id] ?? throw new \LogicException('No service ' . $id);
			}

			public function has(string $id): bool {
				return isset($this->services[$id]);
			}
		};
		return new class($settings, $hotState ?? Server::get(HotState::class), $context, $gate ?? new LoginGate(FixedCaches::none(), Server::get(CoreSession::class)), Server::get(ITimeFactory::class), $container, $logger ?? Server::get(LoggerInterface::class), array_keys($steps)) extends LoginListener {
			/**
			 * @param list<class-string<ILoginStep>> $only
			 */
			public function __construct(
				AppSettings $settings,
				HotState $hotState,
				RequestContext $context,
				LoginGate $gate,
				ITimeFactory $timeFactory,
				ContainerInterface $container,
				LoggerInterface $logger,
				private array $only,
			) {
				parent::__construct($settings, $hotState, $context, $gate, $timeFactory, $container, $logger);
			}

			#[\Override]
			protected function steps(): array {
				return $this->only;
			}
		};
	}

	/**
	 * A container for the login listener: the request's services, then the steps.
	 */
	public static function withRequest(ContainerInterface $steps, IRequest $request, RemoteAddressResolver $addresses, RequestContext $context): ContainerInterface {
		$services = [
			RemoteAddressResolver::class => $addresses,
			LoginClassifier::class => new LoginClassifier($request, $context),
			IRequest::class => $request,
		];
		return new class($services, $steps) implements ContainerInterface {
			/** @param array<string, object> $services */
			public function __construct(
				private readonly array $services,
				private readonly ContainerInterface $steps,
			) {
			}

			public function get(string $id): mixed {
				return $this->services[$id] ?? $this->steps->get($id);
			}

			public function has(string $id): bool {
				return isset($this->services[$id]) || $this->steps->has($id);
			}
		};
	}
}
