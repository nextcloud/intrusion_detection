<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Token\IToken;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The security change log (concept section 7): one entry per change, from
 * core's real code paths, with the email addresses masked.
 */
#[Group('DB')]
class SecurityChangeLogTest extends TakeoverTestCase {
	public function testAnEmailChangeKeepsBothAddressesMasked(): void {
		$user = $this->newUser('ids-log', 'owner@example.com');
		$session = $this->loginAs($user, false);
		$user->setSystemEMailAddress('Other@Example.org');

		$rows = $this->changes($user->getUID());
		$this->assertCount(1, $rows);
		$this->assertSame(SecurityChangeType::EmailChanged->value, $rows[0]['type']);
		$this->assertSame('o***@example.com', $rows[0]['old_value_hint']);
		$this->assertSame('o***@example.org', $rows[0]['new_value_hint']);
		$this->assertSame($session['id'], $rows[0]['session_token_id']);
		$this->assertSame(self::IP, $rows[0]['ip']);
		$this->assertSame($user->getUID(), $rows[0]['actor_uid']);

		$encrypted = Server::get(SecurityChangeMapper::class)->notifyTo($rows[0]['id']);
		$this->assertNotNull($encrypted);
		$this->assertStringNotContainsString('owner@example.com', $encrypted, 'The previous address is kept encrypted only');
	}

	public function testTheSameAddressInAnotherCaseIsNoChange(): void {
		$user = $this->newUser('ids-log', 'owner@example.com');
		$this->loginAs($user, false);
		$user->setSystemEMailAddress('OWNER@example.com');
		$this->assertSame([], $this->changes($user->getUID()));
	}

	public function testAPasswordChange(): void {
		$user = $this->newUser('ids-log');
		$this->loginAs($user, false);
		$user->setPassword('A-new-test-password-for-the-user');
		$this->assertSame([SecurityChangeType::PasswordChanged->value], array_column($this->changes($user->getUID()), 'type'));
	}

	public function testSecondFactorsAddedRemovedAndTurnedOff(): void {
		$user = $this->newUser('ids-log');
		$this->loginAs($user, false);
		$registry = Server::get(IRegistry::class);
		$totp = $this->provider('ids_totp');
		$key = $this->provider('ids_webauthn');

		$registry->enableProviderFor($totp, $user);
		$registry->enableProviderFor($key, $user);
		$registry->disableProviderFor($key, $user);
		$registry->disableProviderFor($totp, $user);

		$rows = $this->changes($user->getUID());
		$this->assertSame([
			SecurityChangeType::SecondFactorAdded->value,
			SecurityChangeType::SecondFactorAdded->value,
			SecurityChangeType::SecondFactorRemoved->value,
			SecurityChangeType::SecondFactorDisabled->value,
		], array_column($rows, 'type'), 'Removing the last one turns two-factor authentication off');
		$this->assertSame(['ids_totp', 'ids_webauthn', 'ids_webauthn', 'ids_totp'], array_column($rows, 'detail'));
	}

	public function testCoreRecordingAnUnknownProviderStateIsNoChange(): void {
		$user = $this->newUser('ids-log');
		$this->loginAs($user, false);
		// At a login core records the state of every provider it has none for yet, here the backup codes.
		Server::get(TwoFactorManager::class)->getProviderSet($user);
		$this->assertArrayHasKey('backup_codes', Server::get(IRegistry::class)->getProviderStates($user), 'Core recorded the state');
		$this->assertSame([], $this->changes($user->getUID(), null));
	}

	public function testAppPasswordsCreatedAndRevokedButNotSessionsEnded(): void {
		$user = $this->newUser('ids-log');
		$this->loginAs($user, false);
		$token = $this->token($user, IToken::PERMANENT_TOKEN, 'Sync client');
		Server::get(IEventDispatcher::class)->dispatchTyped(new AppPasswordCreatedEvent($this->tokens->getTokenById($token['id'])));
		$session = $this->token($user, IToken::TEMPORARY_TOKEN, 'Firefox');

		$this->tokens->invalidateTokenById($user->getUID(), $token['id']);
		$this->tokens->invalidateTokenById($user->getUID(), $session['id']);

		$rows = $this->changes($user->getUID());
		$this->assertSame([SecurityChangeType::AppPasswordCreated->value, SecurityChangeType::AppPasswordRevoked->value], array_column($rows, 'type'));
		$this->assertSame([$token['id'], $token['id']], array_column($rows, 'ref_id'));
		$this->assertSame('Sync client', $rows[1]['detail']);
	}

	public function testAConnectedDeviceIsOneChange(): void {
		$user = $this->newUser('ids-log');
		$this->loginAs($user, false);
		$token = $this->tokens->getTokenById($this->token($user, IToken::PERMANENT_TOKEN, 'Phone')['id']);
		$dispatcher = Server::get(IEventDispatcher::class);
		// Core's login flow dispatches both, in this order.
		$dispatcher->dispatchTyped(new AppPasswordCreatedEvent($token));
		$dispatcher->dispatchTyped(new LoginFlowV2GrantedEvent($token, '198.51.100.4', time() - 30));

		$this->assertSame([SecurityChangeType::DeviceConnected->value], array_column($this->changes($user->getUID()), 'type'));
	}

	public function testAChangeWithoutASessionIsTheSystems(): void {
		$user = $this->newUser('ids-log');
		$this->sessionUser = null;
		$user->setPassword('A-new-test-password-for-the-user');
		$rows = $this->changes($user->getUID(), SecurityChangeLog::VIA_SYSTEM);
		$this->assertNotSame([], $rows);
		$this->assertSame([SecurityChangeType::PasswordChanged->value], array_values(array_unique(array_column($rows, 'type'))));
		$this->assertSame([], $this->changes($user->getUID()));
	}

	public function testRetention(): void {
		$mapper = Server::get(SecurityChangeMapper::class);
		$now = time();
		$row = static fn (int $at, ?string $notify): array => [
			'uid' => 'ids-retention', 'type' => 'email_changed', 'via' => 'self', 'actor_uid' => 'ids-retention',
			'old_value_hint' => 'o***@example.com', 'new_value_hint' => null, 'notify_to' => $notify, 'ref_id' => null,
			'detail' => null, 'session_token_id' => null, 'ip' => null, 'created_at' => $at,
		];
		$old = $mapper->insert($row($now - 91 * 86400, null));
		$yesterday = $mapper->insert($row($now - SecurityChangeLog::ADDRESS_TTL - 60, 'encrypted'));
		$recent = $mapper->insert($row($now - 60, 'encrypted'));
		$links = Server::get(LockLinkMapper::class);
		$expired = $links->insert('ids-retention', str_repeat('a', 64), 'o***@example.com', null, null, $now - 8 * 86400, $now - 86400);
		$valid = $links->insert('ids-retention', str_repeat('b', 64), 'o***@example.com', null, null, $now, $now + 86400);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);

		$this->assertNull($mapper->find($old), 'Kept 90 days by default');
		$this->assertNotNull($mapper->find($yesterday));
		$this->assertNull($mapper->notifyTo($yesterday), 'The previous address is kept a day');
		$this->assertSame('encrypted', $mapper->notifyTo($recent));
		$this->assertNull($links->find($expired));
		$this->assertNotNull($links->find($valid));

		$this->settings->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, 7);
		$mapper->insert($row($now - 8 * 86400, null));
		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertCount(2, $mapper->findSince('ids-retention', 0, 10), 'The retention setting applies');
	}

	private function provider(string $id): IProvider {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn($id);
		$provider->method('getDisplayName')->willReturn($id);
		return $provider;
	}

	protected function tearDown(): void {
		foreach (['ids_totp', 'ids_webauthn'] as $id) {
			Server::get(IRegistry::class)->cleanUp($id);
		}
		parent::tearDown();
	}
}
