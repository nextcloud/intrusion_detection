<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dav;

use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionGate;
use OCP\IRequest;
use Sabre\DAV\Exception\NotAuthenticated;

/**
 * Holds a login that waits for its confirmation, or was refused, away from
 * every remote.php entry point, also where the WebDAV plugins of the app
 * ({@see SessionStatePlugin}) never run: an endpoint that lets no app add
 * plugins, or a service another app serves there.
 *
 * - A session that already carries a step-up is refused when the app boots
 *   on remote.php, before the endpoint runs ({@see self::atBoot()}).
 * - A login decided on the request itself, an app sending the password,
 *   is refused at the login when no plugin of the app was added to the
 *   request ({@see self::atLogin()}). Where the plugins run, they answer.
 */
final class RemoteSessionCheck {
	/** Set in the {@see RequestContext} once the app's WebDAV plugins are added to the request's server */
	public const PLUGINS_ADDED = 'dav-plugins-added';
	private const SCRIPT = '/remote.php';

	public function __construct(
		private readonly IRequest $request,
		private readonly SessionGate $gate,
		private readonly SessionMarkers $markers,
	) {
	}

	public static function isRemote(IRequest $request): bool {
		return str_ends_with($request->getScriptName(), self::SCRIPT);
	}

	/**
	 * The step-up rule for a remote.php request of a session with a
	 * step-up; null for any other request.
	 */
	public function atBoot(): ?SessionBlock {
		if (!self::isRemote($this->request) || $this->markers->get(SessionMarkers::STEP_UP) === null) {
			return null;
		}
		return $this->gate->decideStepUpDav($this->request->getMethod(), $this->request->getRequestUri());
	}

	/**
	 * Refuse a login with a step-up on a remote.php request that no plugin
	 * of the app guards. Sabre answers 401 with the reason, as it does for
	 * wrong credentials.
	 *
	 * @throws NotAuthenticated
	 */
	public static function atLogin(IRequest $request, RequestContext $context, LoginConfirmation $confirmation): void {
		if ($confirmation->stepUp === null || $context->get(self::PLUGINS_ADDED) === true || !self::isRemote($request)) {
			return;
		}
		throw new NotAuthenticated(match ($confirmation->status) {
			ConfirmationStatus::RefusedClient => StepUpRule::MESSAGE_CLIENT,
			ConfirmationStatus::Refused => StepUpRule::MESSAGE_REFUSED,
			ConfirmationStatus::Resumed => StepUpRule::MESSAGE_ENDED,
			default => StepUpRule::MESSAGE_PENDING,
		});
	}

	/**
	 * Answer a refused remote.php request with 403, the header that says
	 * why, and the reason, and end it before the endpoint runs.
	 */
	public static function refuse(SessionBlock $block): never {
		http_response_code(403);
		header($block->davHeader . ': required');
		header('Content-Type: text/plain; charset=utf-8');
		echo $block->message;
		exit();
	}
}
