<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapResponder;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrlFacts;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Detection\Explanation;
use OCA\IntrusionDetection\Login\BasicCredentials;
use OCA\IntrusionDetection\Net\FetchMetadata;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\Traps\PendingTrapHit;
use OCA\IntrusionDetection\Traps\TrapPaths;
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
 * A request for one of Nextcloud's own paths costs the normalisation of its
 * path and one array lookup; any other one a regular expression match plus
 * a loop over the custom paths. The check's mode and the responder are only
 * touched on a hit. A hit with credentials (an Authorization header, a
 * session or remember-me cookie) is decided once the request knows whether
 * it is logged in ({@see TrapResponder}): logged-in users and clients never
 * trip it, but made-up credentials do not hide a scanner either.
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
		private readonly AppSettings $appSettings,
		private readonly CheckSettings $settings,
		private readonly RemoteAddressResolver $addresses,
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
		if ($this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false)) {
			return null;
		}
		$uri = $request->getRequestUri();
		$webRoot = dirname($request->getScriptName());
		if (TrapPaths::isPlainNextcloudUri($uri, $webRoot)) {
			return null;
		}
		$path = TrapPaths::normalise($uri, $webRoot);
		if (TrapPaths::isNextcloudPath($path)) {
			return null;
		}
		$trap = $this->match($path);
		if ($trap === null || !$this->appSettings->isEnabled()) {
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
		$autodiscover = $this->appConfig->getValueBool($app, Keys::param(TrapUrl::ID, 'autodiscover'), false);
		$trap = TrapPaths::match($path, true, $autodiscover, $custom);
		if ($trap !== null && in_array($trap, TrapPaths::BUILTIN, true) && !$this->settings->paramBool(TrapUrl::ID, 'builtin_enabled')) {
			// A custom path may cover a built-in one; it still counts while the built-in list is off.
			return TrapPaths::match($path, false, $autodiscover, $custom);
		}
		return $trap;
	}

	private function trapped(IRequest $request, string $path, string $trap): ?GuardDecision {
		$state = $this->settings->modeState(TrapUrl::ID);
		$source = SourceKey::tryFromIp($request->getRemoteAddress());
		if (!$state->runs() || $source === null || $this->addresses->isIgnored($source)) {
			return null;
		}
		$hit = new PendingTrapHit(
			$source,
			facts: new TrapUrlFacts(
				path: mb_substr((string)Explanation::cleanUserAgent($path), 0, self::MAX_STORED_PATH),
				trap: $trap,
				method: substr(preg_replace('/[^A-Z]/', '', strtoupper($request->getMethod())) ?? '', 0, 10),
			),
			userAgent: $request->getHeader('User-Agent'),
			lure: FetchMetadata::isLure($request),
		);
		// Resolved only on a hit, to keep the guard's own dependencies light.
		$responder = $this->container->get(TrapResponder::class);
		if ($this->presentsCredentials($request)) {
			$responder->defer($hit);
			return null;
		}
		return $responder->anonymous($hit);
	}

	/**
	 * Whether the request presents something to log in with: an
	 * Authorization header, Basic credentials PHP parsed, or a Nextcloud
	 * session or remember-me cookie. None of it is verified yet.
	 */
	private function presentsCredentials(IRequest $request): bool {
		return $request->getHeader('Authorization') !== '' || BasicCredentials::fromServer() !== null || $this->hasSessionCookie($request);
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
