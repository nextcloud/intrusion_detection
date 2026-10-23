<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Takeover\AccountLock;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\AnonRateLimit;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\NoTwoFactorRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\Security\ISecureRandom;
use OCP\Util;

/**
 * The page behind the lock link from the email to an account's previous
 * address (concept section 11.15). It is public: whoever reads that
 * mailbox may not have, or no longer have, access to the account.
 *
 * - Opening the link (GET) changes nothing, so mail scanners that fetch
 *   links do not lock anyone out. It shows what locking does and a form.
 *   It is the only route without CSRF protection, because it is opened
 *   from an email and only reads.
 * - Locking (POST) needs core's request token of this browser session and
 *   a one-time nonce that the page put into its form for this link, so it
 *   can only follow the page. The token from the link goes in the form
 *   body, not the URL.
 * - Both are rate limited, and wrong links are throttled like failed logins.
 *
 * Wrong, unknown and expired links look the same. The token is never logged.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class LockLinkController extends Controller {
	public const TEMPLATE = 'lock';
	public const BRUTE_FORCE_ACTION = 'intrusion_detection_lock';
	public const SESSION_NONCE = 'intrusion_detection.lock_nonce';

	public const PAGE_CONFIRM = 'confirm';
	public const PAGE_LOCKED = 'locked';
	public const PAGE_USED = 'used';
	public const PAGE_EXPIRED = 'expired';
	public const PAGE_INVALID = 'invalid';

	public function __construct(
		IRequest $request,
		private readonly LockLinks $links,
		private readonly AccountLock $lock,
		private readonly ISession $session,
		private readonly ISecureRandom $random,
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[PublicPage]
	#[NoCSRFRequired]
	#[NoTwoFactorRequired]
	#[UseSession]
	#[AnonRateLimit(limit: 30, period: 600)]
	#[UserRateLimit(limit: 30, period: 600)]
	#[BruteForceProtection(action: self::BRUTE_FORCE_ACTION)]
	#[FrontpageRoute(verb: 'GET', url: '/lock/{id}/{token}', requirements: ['id' => '\d+', 'token' => '[A-Za-z0-9]{1,64}'])]
	public function show(string $id, #[\SensitiveParameter] string $token): StandaloneTemplateResponse {
		[$state, $link] = $this->links->check($id, $token);
		return match ($state) {
			LockLinks::VALID => $this->confirmPage($id, $token, $link['sent_to_hint'] ?? ''),
			LockLinks::USED => $this->page(self::PAGE_USED),
			LockLinks::EXPIRED => $this->expired(),
			default => $this->invalid($id),
		};
	}

	#[PublicPage]
	#[NoTwoFactorRequired]
	#[UseSession]
	#[AnonRateLimit(limit: 10, period: 600)]
	#[UserRateLimit(limit: 10, period: 600)]
	#[BruteForceProtection(action: self::BRUTE_FORCE_ACTION)]
	#[FrontpageRoute(verb: 'POST', url: '/lock/{id}', requirements: ['id' => '\d+'])]
	public function lock(string $id, #[\SensitiveParameter] string $token = '', #[\SensitiveParameter] string $nonce = ''): StandaloneTemplateResponse {
		[$state, $link] = $this->links->check($id, $token);
		if ($state !== LockLinks::VALID) {
			return match ($state) {
				LockLinks::USED => $this->page(self::PAGE_USED),
				LockLinks::EXPIRED => $this->expired(),
				default => $this->invalid($id),
			};
		}
		if (!$this->takeNonce($id, $nonce)) {
			return $this->confirmPage($id, $token, $link['sent_to_hint'] ?? '', $this->l->t('Please confirm once more on this page.'));
		}
		return match ($this->lock->lock($id, $token)) {
			AccountLock::LOCKED => $this->page(self::PAGE_LOCKED, ['disabled' => true]),
			AccountLock::SESSIONS_ENDED => $this->page(self::PAGE_LOCKED, ['disabled' => false]),
			LockLinks::USED => $this->page(self::PAGE_USED),
			LockLinks::EXPIRED => $this->expired(),
			default => $this->invalid($id),
		};
	}

	private function confirmPage(string $id, #[\SensitiveParameter] string $token, string $sentTo, ?string $error = null): StandaloneTemplateResponse {
		$nonce = $this->random->generate(32, ISecureRandom::CHAR_ALPHANUMERIC);
		$this->session->set(self::SESSION_NONCE, ['link' => $id, 'nonce' => $nonce]);
		$response = $this->page(self::PAGE_CONFIRM, [
			'action' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.LockLink.lock', ['id' => $id]),
			'token' => $token,
			'nonce' => $nonce,
			'sentTo' => $sentTo,
			'error' => $error,
		]);
		if ($error !== null) {
			$response->setStatus(Http::STATUS_BAD_REQUEST);
		}
		return $response;
	}

	/**
	 * The nonce the page put into its form for this link, once.
	 */
	private function takeNonce(string $id, #[\SensitiveParameter] string $nonce): bool {
		$stored = $this->session->get(self::SESSION_NONCE);
		$this->session->remove(self::SESSION_NONCE);
		return is_array($stored) && ($stored['link'] ?? null) === $id
			&& is_string($stored['nonce'] ?? null) && $nonce !== '' && hash_equals($stored['nonce'], $nonce);
	}

	private function invalid(string $id): StandaloneTemplateResponse {
		$response = $this->page(self::PAGE_INVALID);
		$response->setStatus(Http::STATUS_NOT_FOUND);
		$response->throttle(['link' => $id]);
		return $response;
	}

	private function expired(): StandaloneTemplateResponse {
		$response = $this->page(self::PAGE_EXPIRED);
		$response->setStatus(Http::STATUS_GONE);
		return $response;
	}

	/**
	 * @param array<string, mixed> $params
	 */
	private function page(string $mode, array $params = []): StandaloneTemplateResponse {
		Util::addStyle(Application::APP_ID, 'pages');
		$response = new StandaloneTemplateResponse(Application::APP_ID, self::TEMPLATE, array_merge([
			'mode' => $mode,
			'login_url' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
		], $params), 'guest');
		$response->addHeader('Cache-Control', 'no-store');
		$response->addHeader('Referrer-Policy', 'no-referrer');
		$response->addHeader('X-Robots-Tag', 'noindex, nofollow');
		return $response;
	}
}
