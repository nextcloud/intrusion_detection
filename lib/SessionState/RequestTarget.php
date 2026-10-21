<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OC\Core\Controller\CssController;
use OC\Core\Controller\JsController;
use OC\Core\Controller\OCJSController;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\PublicPage;

/**
 * What a logged-in request is about to reach: an AppFramework controller
 * method, or a WebDAV path. Session-state rules decide on it.
 */
final class RequestTarget {
	/**
	 * Controllers of resources every page needs, and their methods (lower
	 * case; null: every public one). Theming is named as a string: the app
	 * may be missing.
	 *
	 * @var array<string, ?list<string>>
	 */
	public const PUBLIC_RESOURCES = [
		CssController::class => ['getcss'],
		JsController::class => ['getjs'],
		OCJSController::class => ['getconfig'],
		'OCA\\Theming\\Controller\\ThemingController' => ['getimage', 'getthemestylesheet', 'getmanifest'],
		'OCA\\Theming\\Controller\\IconController' => null,
	];

	private ?bool $publicPage = null;

	private function __construct(
		public readonly bool $dav,
		/** The HTTP method, upper case */
		public readonly string $httpMethod,
		/** The request URI as the client sent it, with the web root */
		public readonly string $uri,
		private readonly ?Controller $controller,
		public readonly ?string $controllerMethod,
	) {
	}

	public static function app(Controller $controller, string $methodName, string $httpMethod, string $uri): self {
		return new self(false, strtoupper($httpMethod), $uri, $controller, $methodName);
	}

	public static function dav(string $httpMethod, string $uri): self {
		return new self(true, strtoupper($httpMethod), $uri, null, null);
	}

	/**
	 * Whether the target is a method of this controller (or of a subclass),
	 * and if given, that method.
	 *
	 * @param class-string $class
	 */
	public function isController(string $class, ?string $method = null): bool {
		return $this->controller instanceof $class
			&& ($method === null || strcasecmp((string)$this->controllerMethod, $method) === 0);
	}

	/**
	 * A controller method that anyone may call without logging in: theming
	 * styles, translations, avatars and the like.
	 */
	public function isPublicPage(): bool {
		if ($this->publicPage === null) {
			$this->publicPage = false;
			if ($this->controller !== null && $this->controllerMethod !== null && method_exists($this->controller, $this->controllerMethod)) {
				$reflection = new \ReflectionMethod($this->controller, $this->controllerMethod);
				$this->publicPage = $reflection->getAttributes(PublicPage::class) !== []
					|| str_contains((string)$reflection->getDocComment(), '@PublicPage');
			}
		}
		return $this->publicPage;
	}

	/**
	 * A read-only request for what any page needs to render, also the
	 * verify and password pages: styles, scripts, theming images and icons.
	 * An allowlist: other public pages may show account data to a
	 * logged-in session.
	 */
	public function isPublicResource(): bool {
		if (!$this->isReadOnly() || !$this->isPublicPage()) {
			return false;
		}
		foreach (self::PUBLIC_RESOURCES as $class => $methods) {
			if ($this->controller instanceof $class) {
				return $methods === null || in_array(strtolower((string)$this->controllerMethod), $methods, true);
			}
		}
		return false;
	}

	public function isReadOnly(): bool {
		return $this->httpMethod === 'GET' || $this->httpMethod === 'HEAD';
	}
}
