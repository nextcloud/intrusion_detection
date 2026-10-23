<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Controller\AccountSessionsController;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Response\Tokens;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\Authentication\Token\IToken;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * An administrator handling a detection can end every session and app
 * password of the account it is about, without waiting for a response of
 * the app.
 */
#[Group('DB')]
class AccountSessionsTest extends AccountTestCase {
	public function testEveryLoginOfTheAccountIsEnded(): void {
		$alice = $this->newUser('ids-sessions');
		$browser = $this->token($alice, IToken::TEMPORARY_TOKEN, 'Firefox on Linux');
		$app = $this->token($alice, IToken::PERMANENT_TOKEN, 'Calendar app');
		$bob = $this->newUser('ids-sessions-other');
		$other = $this->token($bob, IToken::TEMPORARY_TOKEN, 'Firefox on Linux');

		$response = $this->controller()->end($this->detectionAbout($alice->getUID())->getId());

		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['ended' => 2], $response->getData());
		$this->assertFalse($this->tokenExists($browser['id']));
		$this->assertFalse($this->tokenExists($app['id']));
		$this->assertTrue($this->tokenExists($other['id']), 'Only the account of the detection');
	}

	public function testADetectionAboutNoAccountHasNothingToEnd(): void {
		$this->expectException(OCSNotFoundException::class);
		$this->controller()->end($this->detectionAbout(null)->getId());
	}

	public function testItNeedsTheAdministratorsPassword(): void {
		$attributes = (new \ReflectionMethod(AccountSessionsController::class, 'end'))->getAttributes(PasswordConfirmationRequired::class);
		$this->assertCount(1, $attributes);
	}

	private function controller(): AccountSessionsController {
		$this->sessionUser = $this->newUser('ids-sessions-admin');
		return new AccountSessionsController(
			$this->createMock(IRequest::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			new ActorResolver($this->userSession),
			Server::get(DetectionMapper::class),
			Server::get(IUserManager::class),
			Server::get(Tokens::class),
			Server::get(AuditLogger::class),
		);
	}

	private function detectionAbout(?string $uid): Detection {
		$detection = new Detection();
		$detection->setCheckId('password_spraying');
		$detection->setSeverity('high');
		$detection->setEnforced(true);
		$detection->setIp('198.51.100.7');
		$detection->setUid($uid);
		$detection->setExplanationData(['v' => 1, 'check' => 'password_spraying', 'facts' => []]);
		$detection->setActionList([]);
		$detection->setCreatedAt(time());
		$detection->setLastSeenAt(time());
		$detection->setHits(1);
		return Server::get(DetectionMapper::class)->insert($detection);
	}
}
