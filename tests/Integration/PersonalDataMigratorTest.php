<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\AppFramework\Bootstrap\Coordinator;
use OC\AppFramework\Bootstrap\ServiceRegistration;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\PersonalDataMigrator;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Server;
use OCP\UserMigration\IExportDestination;
use OCP\UserMigration\IImportSource;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Output\NullOutput;

/**
 * The user's own security data in a user export: what the security page
 * shows, and nothing about other accounts.
 */
#[Group('DB')]
class PersonalDataMigratorTest extends IntegrationTestCase {
	use CreatesAccounts;

	protected function tearDown(): void {
		$this->deleteAccounts();
		parent::tearDown();
	}

	public function testTheMigratorIsRegistered(): void {
		$migrators = array_map(static fn (ServiceRegistration $r): string => $r->getService(), Server::get(Coordinator::class)->getRegistrationContext()?->getUserMigrators() ?? []);
		$this->assertContains(PersonalDataMigrator::class, $migrators);
	}

	public function testTheExportHoldsWhatTheSecurityPageShows(): void {
		$alice = $this->person('ids-export-alice');
		$bob = $this->person('ids-export-bob');
		$history = Server::get(LoginHistoryMapper::class);
		$history->insert($alice->getUID(), time() - 3600, SourceKey::fromIp('198.51.100.7'), 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0', LoginHistory::METHOD_PASSWORD, false, 'second_factor', null, null);
		$history->insert($bob->getUID(), time() - 3600, SourceKey::fromIp('203.0.113.9'), null, LoginHistory::METHOD_PASSWORD, false, 'none', null, null);
		Server::get(TrustedNetworks::class)->trust($alice->getUID(), SourceKey::fromIp('198.51.100.7'));
		Server::get(SecurityChangeMapper::class)->insert([
			'uid' => $alice->getUID(), 'type' => SecurityChangeType::PasswordChanged->value, 'via' => SecurityChangeLog::VIA_SELF, 'actor_uid' => $alice->getUID(),
			'old_value_hint' => null, 'new_value_hint' => null, 'notify_to' => null, 'ref_id' => null, 'detail' => null, 'session_token_id' => null,
			'ip' => '198.51.100.7', 'created_at' => time() - 1800,
		]);
		$this->storeDetection(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('203.0.113.66'), $alice->getUID()));
		$this->storeDetection(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('203.0.113.67'), $bob->getUID()));

		$files = [];
		$destination = $this->createMock(IExportDestination::class);
		$destination->method('addFileContents')->willReturnCallback(static function (string $path, string $content) use (&$files): void {
			$files[$path] = $content;
		});
		Server::get(PersonalDataMigrator::class)->export($alice, $destination, new NullOutput());

		$this->assertSame([PersonalDataMigrator::PATH], array_keys($files));
		$data = json_decode($files[PersonalDataMigrator::PATH], true, flags: JSON_THROW_ON_ERROR);
		$this->assertSame(['exportedAt', 'logins', 'knownDevices', 'trustedNetworks', 'securityChanges', 'detections'], array_keys($data));
		$this->assertCount(1, $data['logins']);
		$this->assertSame('198.51.100.7', $data['logins'][0]['ip']);
		$this->assertSame('second_factor', $data['logins'][0]['confirmedBy']);
		$this->assertSame('198.51.100.0/24', $data['trustedNetworks'][0]['network']);
		$this->assertCount(1, $data['securityChanges']);
		$this->assertCount(1, $data['detections']);
		$this->assertSame([], $data['knownDevices']);
		$json = $files[PersonalDataMigrator::PATH];
		$this->assertStringNotContainsString($bob->getUID(), $json, 'Nothing about another account');
		$this->assertStringNotContainsString('203.0.113.9', $json);
	}

	public function testNothingIsImported(): void {
		$source = $this->createMock(IImportSource::class);
		$source->expects($this->never())->method('getFileContents');
		Server::get(PersonalDataMigrator::class)->import($this->person('ids-import'), $source, new NullOutput());
	}

	private function person(string $prefix): IUser {
		$user = Server::get(IUserManager::class)->get($this->account($prefix));
		$this->assertNotNull($user);
		return $user;
	}
}
