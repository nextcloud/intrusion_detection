<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialTracker;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\CredentialUse\PresentedCredential;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Guard\GuardDecision;
use OCP\Security\Guard\IRequestGuard;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The stolen credential check (concept section 10.12), before
 * authentication. It never refuses a request.
 *
 * Only requests that carry a credential ({@see PresentedCredential}) are
 * looked at, and only while a memory cache exists: without one the check is
 * unavailable and nothing, not even a setting, is read. On the common path
 * a request then costs one HMAC and one cache get; a cache write follows
 * only when the network changed or every five minutes.
 *
 * When the credential switched networks often enough, the switch is kept in
 * {@see RequestContext} until authentication shows that the credential
 * really logs in ({@see CredentialUseResolver}); a credential that never
 * logs in never becomes a detection. A credential seen for the first time
 * is only written to the cache once it logged in, so made-up credentials
 * cost one cache get and leave nothing behind. Requests from the
 * brute-force allowlist, loopback and the server itself are not tracked.
 */
class CredentialUseGuard implements IRequestGuard {
	private bool $shutdownRegistered = false;

	public function __construct(
		private readonly IConfig $config,
		private readonly Settings $settings,
		private readonly Fingerprinter $fingerprinter,
		private readonly CredentialTracker $tracker,
		private readonly RequestContext $context,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
		private readonly GuardTimer $timer,
	) {
	}

	/**
	 * The same guard on another tracker, for measurements.
	 */
	public function withTracker(CredentialTracker $tracker): self {
		return new self($this->config, $this->settings, $this->fingerprinter, $tracker, $this->context, $this->timeFactory, $this->container, $this->logger, $this->timer);
	}

	#[\Override]
	public function check(IRequest $request): ?GuardDecision {
		$start = $this->timer->start();
		try {
			$this->observe($request);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check a credential for use from two networks', ['exception' => $e]);
		} finally {
			$this->timer->stop($start);
		}
		return null;
	}

	private function observe(IRequest $request): void {
		if ($this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false)) {
			return;
		}
		$credential = PresentedCredential::fromRequest($request, $this->config->getSystemValueString('instanceid', ''));
		if ($credential === null || !$this->tracker->isAvailable() || !$this->runs()) {
			return;
		}
		$source = SourceKey::tryFromIp($request->getRemoteAddress());
		if ($source === null) {
			return;
		}
		$use = new CredentialUse($credential->scheme, $credential->hasSessionCookie);
		$this->context->set(CredentialUseResolver::CONTEXT_KEY, $use);

		$switch = $this->tracker->track(
			$this->fingerprinter->credential($credential->keyMaterial()),
			$source,
			$credential->userTag(),
			$this->timeFactory->getTime(),
			fn (): bool => $this->container->get(RemoteAddressResolver::class)->isIgnored($source),
			false,
			$unknown,
		);
		$use->switch = $switch;
		$use->unknown = $unknown;
		if (($switch !== null || $unknown) && !$this->shutdownRegistered) {
			$this->shutdownRegistered = true;
			$this->registerShutdown($this->resolveAtShutdown(...));
		}
	}

	/**
	 * Whether the check may run: two reads of the app config, which is
	 * loaded for the request, and no check definition. The address guard
	 * runs first and only hands on a verdict while the app is enabled.
	 * Learning mode does not matter here: Observe records like Protect, and
	 * the response engine applies the effective mode.
	 */
	private function runs(): bool {
		return ($this->context->verdict() !== null || $this->settings->isEnabled())
			&& $this->settings->configuredMode(TokenConcurrentUse::ID) !== Mode::Off;
	}

	/**
	 * The last chance for a pending switch, for entry points where no
	 * session-state rule runs.
	 */
	public function resolveAtShutdown(): void {
		try {
			$this->container->get(CredentialUseResolver::class)->resolve(true);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a credential used from two networks', ['exception' => $e]);
		}
	}

	protected function registerShutdown(\Closure $callback): void {
		register_shutdown_function($callback);
	}
}
