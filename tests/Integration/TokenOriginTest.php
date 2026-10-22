<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Listener\AppPasswordCreatedListener;
use OCA\IntrusionDetection\Response\TokenRevoker;
use OCA\IntrusionDetection\Response\Tokens;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Token\IToken;
use OCP\IRequest;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Where app passwords come from (concept section 7, ids_token_origin), and
 * revoking one token with what was created from it (section 11.4).
 */
#[Group('DB')]
class TokenOriginTest extends AccountTestCase {
	private TokenOriginMapper $origins;
	private string $remoteAddress = '203.0.113.20';

	protected function setUp(): void {
		parent::setUp();
		$this->origins = Server::get(TokenOriginMapper::class);
	}

	public function testAnAppPasswordCreatedInABrowserSessionRecordsThatSessionAndTheAddress(): void {
		$user = $this->newUser('ids-origin');
		$session = $this->startSession($user);
		$appPassword = $this->token($user, IToken::PERMANENT_TOKEN, 'Desktop client');

		$this->listener()->handle(new AppPasswordCreatedEvent($this->tokens->getTokenById($appPassword['id'])));

		$row = $this->origins->find($appPassword['id']);
		$this->assertNotNull($row);
		$this->assertSame($user->getUID(), $row['uid']);
		$this->assertSame('203.0.113.20', $row['ip']);
		$this->assertSame($session['id'], $row['session_token_id']);
		$this->assertEqualsWithDelta(time(), $row['created_at'], 5);
		$this->assertStringNotContainsString($appPassword['secret'], json_encode($this->allOrigins(), JSON_THROW_ON_ERROR));
		$this->assertStringNotContainsString($session['secret'], json_encode($this->allOrigins(), JSON_THROW_ON_ERROR));
	}

	public function testAnAppPasswordCreatedWithAnotherAppPasswordRecordsThatOne(): void {
		$user = $this->newUser('ids-origin');
		$parent = $this->token($user, IToken::PERMANENT_TOKEN, 'Old client');
		// Logged in with an app password: the session id is no token, core keeps the token's id.
		$this->session->id = 'not-a-token';
		$this->session->set('token-id', $parent['id']);
		$child = $this->token($user, IToken::PERMANENT_TOKEN, 'Rotated client');

		$this->listener()->handle(new AppPasswordCreatedEvent($this->tokens->getTokenById($child['id'])));

		$this->assertSame($parent['id'], $this->origins->find($child['id'])['session_token_id'] ?? null);
	}

	public function testWithoutASessionOnlyTheAccountIsKnown(): void {
		$user = $this->newUser('ids-origin');
		$this->remoteAddress = '';
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Created with occ');

		$this->listener()->handle(new AppPasswordCreatedEvent($this->tokens->getTokenById($token['id'])));

		$row = $this->origins->find($token['id']);
		$this->assertNotNull($row);
		$this->assertNull($row['ip']);
		$this->assertNull($row['session_token_id']);
	}

	public function testNothingIsRecordedWhileTheAppIsSwitchedOff(): void {
		$this->appConfig->setValueBool('intrusion_detection', GlobalSettings::ENABLED, false);
		$user = $this->newUser('ids-origin');
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Client');
		$this->listener()->handle(new AppPasswordCreatedEvent($this->tokens->getTokenById($token['id'])));
		$this->assertNull($this->origins->find($token['id']));
	}

	public function testOriginsAreKeptForThirtyDays(): void {
		$this->origins->record(1001, 'alice', '203.0.113.1', null, time() - 31 * 86400);
		$this->origins->record(1002, 'alice', '203.0.113.1', null, time() - 29 * 86400);
		$job = Server::get(Cleanup::class);
		$job->setLastRun(0);
		$job->start(Server::get(\OCP\BackgroundJob\IJobList::class));
		$this->assertNull($this->origins->find(1001));
		$this->assertNotNull($this->origins->find(1002));
	}

	public function testRevokingATokenAlsoRevokesWhatWasCreatedWithItAndNothingElse(): void {
		$user = $this->newUser('ids-revoke');
		$stolen = $this->token($user, IToken::PERMANENT_TOKEN, 'Stolen client');
		$child = $this->token($user, IToken::PERMANENT_TOKEN, 'Created with the stolen one');
		$unrelated = $this->token($user, IToken::PERMANENT_TOKEN, 'Phone');
		$this->origins->record($child['id'], $user->getUID(), '203.0.113.9', $stolen['id'], time());
		$this->origins->record($unrelated['id'], $user->getUID(), '203.0.113.9', null, time());
		$someoneElse = $this->newUser('ids-revoke');
		$foreign = $this->token($someoneElse, IToken::PERMANENT_TOKEN, 'Other account');

		$revoker = new TokenRevoker(Server::get(Tokens::class), $this->origins, Server::get(AuditLogger::class));
		$result = $revoker->revoke($user->getUID(), $stolen['id']);

		$this->assertSame(['id' => $stolen['id'], 'name' => 'Stolen client'], $result['token']);
		$this->assertSame([['id' => $child['id'], 'name' => 'Created with the stolen one']], $result['tokens']);
		$this->assertFalse($this->tokenExists($stolen['id']));
		$this->assertFalse($this->tokenExists($child['id']));
		$this->assertTrue($this->tokenExists($unrelated['id']));

		// A token of another account is never touched, whatever id is given.
		$this->assertNull($revoker->revoke($user->getUID(), $foreign['id'])['token']);
		$this->assertTrue($this->tokenExists($foreign['id']));
		// Revoking again is harmless.
		$this->assertSame(['token' => null, 'tokens' => []], $revoker->revoke($user->getUID(), $stolen['id']));
	}

	private function listener(): AppPasswordCreatedListener {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		return new AppPasswordCreatedListener(
			$this->appSettings(),
			$this->origins,
			$this->currentSession,
			$request,
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	private function allOrigins(): array {
		$result = $this->db->getQueryBuilder()->select('*')->from(TokenOriginMapper::TABLE)->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		return $rows;
	}
}
