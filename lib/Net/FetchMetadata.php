<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCP\IRequest;

/**
 * What the browser's fetch metadata headers (`Sec-Fetch-*`) and its Origin
 * say about how a request came about.
 *
 * A request is a possible lure when a browser made it for another site's
 * page or an email: to embed a URL (an image, a script, a frame), because the
 * other site sent the browser there, or because its page submitted a form.
 * Any web page or HTML email can make a visitor's browser do that, and the
 * visitor's cookies usually stay behind, so the request looks anonymous.
 *
 * Another site started the request when `Sec-Fetch-Site` says `cross-site`
 * or `same-site`: another host of the same registrable domain (a webmail,
 * the homepage next to this server) counts as another site, since other
 * people may publish there. A browser that sends no fetch metadata names the
 * other site in the Origin header instead (or `null`, for a sandboxed frame
 * or after a redirect), which it adds to every request but a GET or HEAD
 * from a link or an embed.
 *
 * Another site's page can only make the requests that need no CORS
 * preflight, so only these can be lures:
 * - GET and HEAD: another site started it, or it embeds a URL (`no-cors`
 *   mode or an embedding destination);
 * - POST that another site started, as a form, `fetch()`, a beacon, a link
 *   ping or a policy report: a navigation, `no-cors` or `cors` mode, a
 *   document, frame or empty destination (or a report), and a body a page may
 *   send without a preflight (a form, plain text) or that the browser sets
 *   itself (`text/ping`, `application/csp-report`);
 * - OPTIONS that another site started as a CORS preflight, which a page
 *   causes by asking for any other request.
 * Anything else from another site, such as PUT, DELETE, PROPFIND, JSON or a
 * header only scripts send, reaches the server only after the server allowed
 * it, so it is never a lure.
 *
 * A request whose Origin or Referer is this server came from one of its own
 * pages, not from another site, so it is no lure either; scanners often
 * name the server they scan as the referrer. Scripts and scanners usually
 * send no fetch metadata and no Origin, and requests that name an attack
 * tool or scripting library as their user agent are never lures.
 *
 * A scanner can still send the headers on purpose. That is why only the
 * checks that another site's page can trigger honour lures (a trap URL, an
 * injection probe, an unknown share link), and they still record the
 * request; they just do not block its address.
 */
final class FetchMetadata {
	/** Destinations of requests that embed a URL in a page */
	private const EMBEDDED = [
		'audio', 'audioworklet', 'embed', 'font', 'frame', 'iframe', 'image', 'manifest', 'object',
		'paintworklet', 'report', 'script', 'serviceworker', 'sharedworker', 'style', 'track',
		'video', 'worker', 'xslt',
	];

	/** `Sec-Fetch-Site` values of a request another host started */
	private const OTHER_SITE = ['cross-site', 'same-site'];

	/** `Sec-Fetch-Mode` values of a POST another site's page can make */
	private const POST_MODES = ['', 'navigate', 'no-cors', 'cors'];

	/** `Sec-Fetch-Dest` values of such a POST: a form's target, a script's or ping's request, a report */
	private const POST_DESTINATIONS = ['', 'document', 'iframe', 'frame', 'empty', 'report'];

	/** Body types such a POST can have without a preflight, or that the browser sets itself */
	private const POST_TYPES = [
		'', 'application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain',
		'text/ping', 'application/csp-report',
	];

	/** Headers that only scripts send, which another site's page cannot add without a preflight */
	private const SCRIPT_HEADERS = ['OCS-APIRequest', 'X-Requested-With', 'requesttoken'];

	public static function isLure(IRequest $request): bool {
		if (self::fromThisServer($request) || !self::fromABrowser($request)) {
			return false;
		}
		$mode = self::header($request, 'Sec-Fetch-Mode');
		$dest = self::header($request, 'Sec-Fetch-Dest');
		return match (strtoupper($request->getMethod())) {
			'GET', 'HEAD' => self::fromOtherSite($request) || $mode === 'no-cors' || in_array($dest, self::EMBEDDED, true),
			'POST' => self::fromOtherSite($request)
				&& in_array($mode, self::POST_MODES, true)
				&& in_array($dest, self::POST_DESTINATIONS, true)
				&& in_array(trim(explode(';', self::header($request, 'Content-Type'), 2)[0]), self::POST_TYPES, true),
			'OPTIONS' => self::fromOtherSite($request)
				&& ($mode === '' || $mode === 'cors')
				&& trim($request->getHeader('Access-Control-Request-Method')) !== '',
			default => false,
		};
	}

	/**
	 * Whether the browser says another site started the request: by
	 * `Sec-Fetch-Site`, or by an Origin when it sends no fetch metadata. Only
	 * called once an Origin of this server was ruled out.
	 */
	private static function fromOtherSite(IRequest $request): bool {
		$site = self::header($request, 'Sec-Fetch-Site');
		if ($site !== '') {
			return in_array($site, self::OTHER_SITE, true);
		}
		$origin = self::header($request, 'Origin');
		return $origin === 'null' || self::hostOf($origin) !== null;
	}

	/**
	 * Whether nothing in the request rules out a browser: no attack tool as
	 * the user agent and no header only scripts send.
	 */
	private static function fromABrowser(IRequest $request): bool {
		foreach (self::SCRIPT_HEADERS as $header) {
			if ($request->getHeader($header) !== '') {
				return false;
			}
		}
		return (new AttackTools())->match($request->getHeader('User-Agent')) === null;
	}

	/**
	 * A header's value, trimmed and lowercased.
	 */
	private static function header(IRequest $request, string $name): string {
		return strtolower(trim($request->getHeader($name)));
	}

	/**
	 * Whether the Origin or the Referer names the host the request was sent to.
	 */
	private static function fromThisServer(IRequest $request): bool {
		$server = strtolower($request->getServerHost());
		if ($server === '') {
			return false;
		}
		foreach (['Origin', 'Referer'] as $header) {
			if (self::hostOf($request->getHeader($header)) === $server) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The host of a URL, with its port if the URL names one, lowercased.
	 */
	private static function hostOf(string $url): ?string {
		$parts = parse_url(trim($url));
		if (!is_array($parts) || !isset($parts['host'])) {
			return null;
		}
		return strtolower($parts['host']) . (isset($parts['port']) ? ':' . $parts['port'] : '');
	}
}
