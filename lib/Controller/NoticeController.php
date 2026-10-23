<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\SessionState\ILoginFlowPage;
use OCA\IntrusionDetection\SessionState\LoginFlowRoute;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Util;

/**
 * The security notice before the start page, for users Nextcloud could
 * only tell inside Nextcloud ({@see LoginNotices}, concept section 11.1):
 * the events since the first one that was not shown, each with the "Was
 * this you?" answers where it asks. Continuing clears the notice.
 *
 * Only ever the current user's own events. The answers follow
 * {@see WasThisYouService}: "Yes, it was me" needs a recent password
 * confirmation and is refused from the session an event is about. Every
 * change is a CSRF-protected POST, rate limited per user.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class NoticeController extends Controller implements ILoginFlowPage {
	public const TEMPLATE = 'notice';
	/** At most this many events are shown */
	public const MAX = 20;
	/** Never continued to: the notice itself */
	public const EXCLUDED = ['/apps/' . Application::APP_ID . '/notice'];

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly LoginNotices $notices,
		private readonly PersonalDetections $personal,
		private readonly WasThisYouService $answers,
		private readonly IURLGenerator $urlGenerator,
		private readonly LocalRedirect $redirect,
		private readonly IL10N $l,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[\Override]
	public static function loginFlowRoute(): LoginFlowRoute {
		return LoginFlowRoute::Notice;
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[FrontpageRoute(verb: 'GET', url: '/notice')]
	public function show(string $redirect_url = ''): Response {
		$user = $this->userSession->getUser();
		if ($user === null || $this->notices->shownSince($user->getUID()) === null) {
			return $this->continue($redirect_url);
		}
		return $this->page($user, $redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 20, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/notice/continue')]
	public function done(string $redirect_url = ''): RedirectResponse {
		$user = $this->userSession->getUser();
		if ($user !== null) {
			$this->notices->done($user->getUID());
		}
		return $this->continue($redirect_url);
	}

	#[NoAdminRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/notice/{id}/deny', requirements: ['id' => '\d+'])]
	public function deny(int $id, string $redirect_url = ''): Response {
		return $this->answer($id, $redirect_url, false);
	}

	#[NoAdminRequired]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/notice/{id}/confirm', requirements: ['id' => '\d+'])]
	public function confirm(int $id, string $redirect_url = ''): Response {
		return $this->answer($id, $redirect_url, true);
	}

	private function answer(int $id, string $redirectUrl, bool $yes): Response {
		$user = $this->userSession->getUser();
		if ($user === null || $this->notices->shownSince($user->getUID()) === null) {
			return $this->continue($redirectUrl);
		}
		try {
			$answered = $yes ? $this->answers->confirm($user, $id) : $this->answers->deny($user, $id);
		} catch (AnswerException $e) {
			return $this->page($user, $redirectUrl, $e->reason === AnswerException::SESSION_NOT_ALLOWED
				? $this->l->t('For your safety, this answer cannot be given from this session. Answer from another device, after a login with your second factor or from a device you remembered.')
				: $this->l->t('This event cannot be answered any more.'), status: Http::STATUS_BAD_REQUEST);
		}
		if (!$this->userSession->isLoggedIn()) {
			// "No" ended the session the event was about, and that was this one.
			return new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm'));
		}
		return $this->page($user, $redirectUrl, notice: match (true) {
			$yes => $this->l->t('Thank you. The network of this event is trusted for a while.'),
			$answered->getUserVerdict() === null => $this->l->t('Your administrator was told. To end the sessions of this event, answer again after a login with your second factor or an email code, or from a device you remembered.'),
			default => $this->l->t('Thank you. Your answer was recorded and your administrator was told.'),
		});
	}

	private function page(IUser $user, string $redirectUrl, ?string $error = null, ?string $notice = null, int $status = Http::STATUS_OK): StandaloneTemplateResponse {
		$since = $this->notices->shownSince($user->getUID()) ?? 0;
		$events = array_map(
			fn (Detection $d): array => $this->personal->present($d, $user) + [
				'denyAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Notice.deny', ['id' => $d->getId()]),
				'confirmAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Notice.confirm', ['id' => $d->getId()]),
			],
			$this->personal->find($user, $since, self::MAX),
		);
		Util::addStyle(Application::APP_ID, 'pages');
		$response = new StandaloneTemplateResponse(Application::APP_ID, self::TEMPLATE, [
			'events' => $events,
			'error' => $error,
			'notice' => $notice,
			'redirect_url' => LocalRedirect::isSafe($redirectUrl, self::EXCLUDED) ? $redirectUrl : '',
			'continueAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Notice.done'),
			'logout_url' => $this->urlGenerator->getLogoutUrl(),
		], 'guest');
		$response->setStatus($status);
		return $response;
	}

	private function continue(string $redirectUrl): RedirectResponse {
		return new RedirectResponse($this->redirect->target($redirectUrl, self::EXCLUDED));
	}
}
