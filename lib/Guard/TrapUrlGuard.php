<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\Explanation;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Traps\TrapPaths;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Guard\GuardDecision;
use OCP\Security\Guard\IRequestGuard;
use Psr\Container\ContainerInterface;

/**
 * Trap URLs: a request for a path no legitimate Nextcloud client requests
 * blocks its source.
 *
 * Only requests without credentials are looked at: no Authorization header
 * and no Nextcloud session or remember-me cookie, so logged-in users and
 * clients can never trip it. On that path the cost is one regular
 * expression match plus a loop over the custom paths; the check's mode and
 * the response engine are only touched on a hit.
 *
 * Registered after the address guard, so an address that is already blocked
 * never gets here.
 */
class TrapUrlGuard implements IRequestGuard {
	/** Cookies that mean the client has, or had, a Nextcloud session */
	public const SESSION_COOKIES = ['nc_session_id', 'nc_token', 'nc_username', 'oc_sessionPassphrase'];
	public const MAX_STORED_PATH = 200;

	public function __construct(
		private readonly IConfig $config,
		private readonly IAppConfig $appConfig,
		private readonly Settings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly GuardTimer $timer,
	) {
	}

	#[\Override]
	public function check(IRequest $request): ?GuardDecision {
		$start = $this->timer->start();
		try {
			return $this->trap($request);
		} finally {
			$this->timer->stop($start);
		}
	}

	private function trap(IRequest $request): ?GuardDecision {
		if ($request->getHeader('Authorization') !== '' || $this->hasSessionCookie($request)) {
			return null;
		}
		if ($this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false)) {
			return null;
		}
		$path = TrapPaths::normalise($request->getRequestUri(), dirname($request->getScriptName()));
		$trap = $this->match($path);
		if ($trap === null || !$this->settings->isEnabled()) {
			return null;
		}
		return $this->trapped($request, $path, $trap);
	}

	/**
	 * The trap a normalised path hits, honouring the check's settings. Reads
	 * the custom paths straight from the app config, which is cached for the
	 * request, so the common path builds no check definitions.
	 */
	private function match(string $path): ?string {
		$app = Application::APP_ID;
		$custom = array_values(array_filter(
			$this->appConfig->getValueArray($app, Keys::param(TrapUrl::ID, 'paths'), []),
			static fn (mixed $p): bool => is_string($p) && str_starts_with($p, '/'),
		));
		$trap = TrapPaths::match($path, true, $this->appConfig->getValueBool($app, Keys::param(TrapUrl::ID, 'autodiscover'), false), $custom);
		if ($trap !== null && in_array($trap, TrapPaths::BUILTIN, true) && !$this->settings->paramBool(TrapUrl::ID, 'builtin_enabled')) {
			return null;
		}
		return $trap;
	}

	private function trapped(IRequest $request, string $path, string $trap): ?GuardDecision {
		$state = $this->settings->modeState(TrapUrl::ID);
		$source = SourceKey::tryFromIp($request->getRemoteAddress());
		if (!$state->runs() || $source === null || $this->addresses->isIgnored($source)) {
			return null;
		}
		// Resolved only on a hit, to keep the guard's own dependencies light.
		$engine = $this->container->get(ResponseEngine::class);
		$detection = $engine->handle(new DetectionDraft(
			checkId: TrapUrl::ID,
			source: $source,
			facts: [
				'path' => mb_substr((string)Explanation::cleanUserAgent($path), 0, self::MAX_STORED_PATH),
				'trap' => $trap,
				'method' => substr(preg_replace('/[^A-Z]/', '', strtoupper($request->getMethod())) ?? '', 0, 10),
			],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $request->getHeader('User-Agent'),
		));
		if ($detection === null || !$detection->isEnforced()) {
			return null;
		}
		$verdict = $this->container->get(AddressResolver::class)->resolve($source);
		$now = $this->timeFactory->getTime();
		if (!$verdict->isDenied($now)) {
			return null;
		}
		return GuardDecision::deny($verdict->denyUntil - $now, $verdict->reference);
	}

	private function hasSessionCookie(IRequest $request): bool {
		$instanceId = $this->config->getSystemValueString('instanceid', '');
		if ($instanceId !== '' && $request->getCookie($instanceId) !== null) {
			return true;
		}
		foreach (self::SESSION_COOKIES as $name) {
			if ($request->getCookie($name) !== null) {
				return true;
			}
		}
		return false;
	}
}
