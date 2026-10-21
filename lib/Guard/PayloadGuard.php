<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Check\Payload\PayloadInspector;
use OCA\IntrusionDetection\Check\Payload\PayloadResponder;
use OCA\IntrusionDetection\Check\Payload\PayloadSettings;
use OCA\IntrusionDetection\Check\Payload\PendingHit;
use OCA\IntrusionDetection\Check\Payload\PreFilter;
use OCA\IntrusionDetection\Check\Payload\RequestParts;
use OCA\IntrusionDetection\Login\BasicCredentials;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Guard\GuardDecision;
use OCP\Security\Guard\IRequestGuard;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The injection probe check, before routing.
 *
 * Every request costs one pre-filter scan of its path, query string and form
 * fields. The pre-filter runs before the check's mode is read, because it is
 * far cheaper than reading settings; an Off check still does nothing else.
 * Only requests the pre-filter flags load the settings and the matcher.
 *
 * A request without credentials that matches is answered at once: detection,
 * block, and this request refused with the block's reference. A request with
 * credentials is decided once it is known whether it is really logged in
 * ({@see PayloadResponder}). The brute-force allowlist is always honoured.
 * Anything that goes wrong lets the request through.
 */
class PayloadGuard implements IRequestGuard {
	/** Remember-me cookie that logs a browser in without a session */
	public const REMEMBER_ME_COOKIE = 'nc_token';

	public function __construct(
		private readonly IConfig $config,
		private readonly RemoteAddressResolver $addresses,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
		private readonly GuardTimer $timer,
	) {
	}

	#[\Override]
	public function check(IRequest $request): ?GuardDecision {
		$start = $this->timer->start();
		try {
			return $this->inspect($request);
		} finally {
			$this->timer->stop($start);
		}
	}

	private function inspect(IRequest $request): ?GuardDecision {
		if ($this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false)) {
			return null;
		}
		try {
			$uri = $request->getRequestUri();
			// Only what PHP already parsed: the request body itself is never read.
			$post = $request->getMethod() === 'POST' ? $_POST : [];
			// Most requests end here, before the script name is even looked at.
			if (!PreFilter::hit(RequestParts::unfiltered($uri, $post))) {
				return null;
			}
			return $this->decide($request, RequestParts::fromUri($uri, $request->getScriptName(), $post));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not inspect a request for injection probes', ['exception' => $e]);
			return null;
		}
	}

	public function decide(IRequest $request, RequestParts $parts): ?GuardDecision {
		if (!PreFilter::hit($parts)) {
			return null;
		}
		$settings = $this->container->get(PayloadSettings::class);
		$credential = $this->credential($request);
		if (!$settings->anonymousMode()->runs() && ($credential === null || !$settings->authenticatedMode()->runs())) {
			return null;
		}
		$source = SourceKey::tryFromIp($request->getRemoteAddress());
		if ($source === null || $this->addresses->isBypassListed($source)) {
			return null;
		}
		$hit = $this->container->get(PayloadInspector::class)->inspect($parts, $settings->rules());
		if ($hit === null) {
			return null;
		}
		$userAgent = $request->getHeader('User-Agent');
		$userAgent = $userAgent === '' ? null : $userAgent;
		$responder = $this->container->get(PayloadResponder::class);
		if ($credential !== null) {
			$responder->defer(new PendingHit($hit, $source, $credential, $userAgent));
			return null;
		}
		return $responder->anonymous($hit, $source, $userAgent);
	}

	/**
	 * What the request presents to log in, if anything: an Authorization
	 * header, Basic credentials PHP parsed, the session cookie (named after
	 * the instance id) or the remember-me cookie. None of it is verified yet.
	 *
	 * @return PendingHit::CREDENTIAL_*|null
	 */
	private function credential(IRequest $request): ?string {
		$authorization = strtolower(substr(trim($request->getHeader('Authorization')), 0, 7));
		if ($authorization !== '') {
			return match (true) {
				str_starts_with($authorization, 'bearer ') => PendingHit::CREDENTIAL_BEARER,
				str_starts_with($authorization, 'basic ') => PendingHit::CREDENTIAL_BASIC,
				default => PendingHit::CREDENTIAL_OTHER,
			};
		}
		if (BasicCredentials::fromServer() !== null) {
			return PendingHit::CREDENTIAL_BASIC;
		}
		$sessionCookie = $this->config->getSystemValueString('instanceid', '');
		if ($sessionCookie !== '' && $request->getCookie($sessionCookie) !== null) {
			return PendingHit::CREDENTIAL_SESSION;
		}
		return $request->getCookie(self::REMEMBER_ME_COOKIE) !== null ? PendingHit::CREDENTIAL_REMEMBER_ME : null;
	}
}
