<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCP\IRequest;

/**
 * What the browser's fetch metadata headers (`Sec-Fetch-*`) say about how a
 * request came about.
 *
 * A request is a possible lure when a browser fetched a URL for another
 * site's page or an email: to embed it (an image, a script, a frame), or
 * because the other site sent the browser there. Any web page or HTML email
 * can make a visitor's browser do that with a GET request, so only GET and
 * HEAD requests can be lures. Only browsers send these headers; scripts and
 * scanners usually send none, and requests without them are never lures.
 *
 * A request whose Origin or Referer is this server came from one of its own
 * pages, not from another site, so it is no lure either; scanners often
 * name the server they scan as the referrer.
 *
 * A scanner can still send the headers on purpose. That is why only the
 * checks that a plain link can trigger honour lures (a trap URL, an
 * injection probe in a URL, an unknown share link), and they still record
 * the request; they just do not block its address.
 */
final class FetchMetadata {
	/** Destinations of requests that embed a URL in a page */
	private const EMBEDDED = [
		'audio', 'audioworklet', 'embed', 'font', 'frame', 'iframe', 'image', 'manifest', 'object',
		'paintworklet', 'report', 'script', 'serviceworker', 'sharedworker', 'style', 'track',
		'video', 'worker', 'xslt',
	];

	public static function isLure(IRequest $request): bool {
		$method = strtoupper($request->getMethod());
		if ($method !== 'GET' && $method !== 'HEAD') {
			return false;
		}
		$foreign = strtolower(trim($request->getHeader('Sec-Fetch-Site'))) === 'cross-site'
			|| strtolower(trim($request->getHeader('Sec-Fetch-Mode'))) === 'no-cors'
			|| in_array(strtolower(trim($request->getHeader('Sec-Fetch-Dest'))), self::EMBEDDED, true);
		return $foreign && !self::fromThisServer($request);
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
