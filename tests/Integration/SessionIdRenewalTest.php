<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\Authentication\Exceptions\InvalidTokenException;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\Group;

/**
 * A confirmed login continues under a new session id, with the same
 * session token, so that what the app recorded about the session by its
 * token id stays linked.
 */
#[Group('DB')]
class SessionIdRenewalTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-renewal', 'alice@example.com');
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testConfirmingWithTheEmailCodeRenewsTheSessionIdAndKeepsItsToken(): void {
		$token = $this->waitingLogin();

		$this->verifyController()->confirm('482915');

		$this->assertNotSame($token['secret'], $this->session->id, 'The session has a new id');
		$this->assertSessionKeeps($token);
		$this->assertSame([$token['secret']], $this->magicCookieRenewedFrom, 'A remember-me cookie of the old id follows it');
	}

	public function testConfirmingWithTheSecondFactorRenewsTheSessionIdAndKeepsItsToken(): void {
		$this->hasSecondFactor = true;
		$token = $this->waitingLogin();

		$this->passChallenge($this->alice);

		$this->assertNotSame($token['secret'], $this->session->id, 'The session has a new id');
		$this->assertSessionKeeps($token);
	}

	public function testARememberedBrowserComesBackConfirmedThroughTheRenewedId(): void {
		$token = $this->waitingLogin();
		$this->verifyController()->confirm('482915');
		$renewed = (string)$this->session->id;

		// The browser comes back with its remember-me cookie, which core moved to the renewed id.
		$this->session->clear();
		$this->nextRequest();
		$this->session->id = bin2hex(random_bytes(32));
		$this->cookies['nc_session_id'] = $renewed;
		$this->method = 'GET';
		$this->tokens->renewSessionToken($renewed, $this->session->id);
		$this->loginThroughTheApp($this->alice, new UserLoggedInWithCookieEvent($this->alice, $this->alice->getUID(), null));

		$this->assertNull($this->state->get(SessionMarkers::STEP_UP), 'Not taken for a login that was never confirmed');
		$this->assertNotNull($this->sessionUser);
		$this->assertSame([], $this->detectionsOf('step_up_failed'));
		$this->assertSame(LoginHistory::STEP_UP_CONFIRMED, $this->historyOf($token['id'])?->stepUp);
	}

	public function testWithoutCoresRenewalTheSessionKeepsItsId(): void {
		$this->sessionIdRenewal = false;
		$token = $this->waitingLogin();

		$this->verifyController()->confirm('482915');

		$this->assertSame($token['secret'], $this->session->id);
		$this->assertSame($token['id'], $this->tokens->getToken($token['secret'])->getId());
		$this->assertSame([], $this->magicCookieRenewedFrom);
		$this->assertSame(LoginHistory::STEP_UP_CONFIRMED, $this->historyOf($token['id'])?->stepUp);
	}

	/**
	 * A login from the flagged address that waits for its confirmation,
	 * after its first request linked the login history to its token.
	 *
	 * @return array{id: int, secret: string}
	 */
	private function waitingLogin(): array {
		$token = $this->startSession($this->alice);
		$this->cookies = ['nc_username' => $this->alice->getUID(), 'nc_token' => 'remember-me-token', 'nc_session_id' => $token['secret']];
		$this->loginThroughTheApp($this->alice);
		$this->history()->linkSession($this->alice->getUID());
		$this->assertNotNull($this->stepUp());
		$this->assertSame(LoginHistory::STEP_UP_PENDING, $this->historyOf($token['id'])?->stepUp);
		return $token;
	}

	/**
	 * @param array{id: int, secret: string} $token
	 */
	private function assertSessionKeeps(array $token): void {
		$this->assertSame($token['id'], $this->tokens->getToken((string)$this->session->id)->getId(), 'The session token is the same row');
		$this->assertTrue($this->tokenExists($token['id']));
		try {
			$this->tokens->getToken($token['secret']);
			$this->fail('The old session id still finds the token');
		} catch (InvalidTokenException) {
		}
		$this->assertSame($token['id'], $this->coreSession->tokenId());
		$this->assertSame(LoginHistory::STEP_UP_CONFIRMED, $this->historyOf($token['id'])?->stepUp, 'The login history stays linked');
		$this->assertNull($this->stepUp());
		$this->assertNotNull($this->sessionUser);
	}

	private function historyOf(int $tokenId): ?LoginHistoryEntry {
		return $this->history()->forSession($this->alice->getUID(), $tokenId);
	}
}
