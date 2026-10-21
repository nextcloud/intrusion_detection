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
 * A request is a possible lure when a browser made it for another site's
 * page, or to embed the URL (an image, a script, a frame), rather than
 * because its user went there: any web page or HTML email can make a
 * visitor's browser request any URL that way. Only browsers send these
 * headers; scripts and scanners usually send none, and requests without
 * them are never lures. A scanner can send them on purpose to avoid being
 * blocked, which is why a lure is still recorded, just not blocked.
 */
final class FetchMetadata {
	/** Destinations of requests that embed a URL in a page */
	private const EMBEDDED = [
		'audio', 'audioworklet', 'embed', 'font', 'frame', 'iframe', 'image', 'manifest', 'object',
		'paintworklet', 'report', 'script', 'serviceworker', 'sharedworker', 'style', 'track',
		'video', 'worker', 'xslt',
	];

	public static function isLure(IRequest $request): bool {
		return strtolower(trim($request->getHeader('Sec-Fetch-Site'))) === 'cross-site'
			|| strtolower(trim($request->getHeader('Sec-Fetch-Mode'))) === 'no-cors'
			|| in_array(strtolower(trim($request->getHeader('Sec-Fetch-Dest'))), self::EMBEDDED, true);
	}
}
