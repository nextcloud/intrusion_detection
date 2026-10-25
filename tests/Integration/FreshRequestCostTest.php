<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\LexiconData;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Perf\FreshRequestProbe;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * What the app loads for a WebDAV request with an app password in a new
 * PHP process (concept section 19): its registration, the config lexicon,
 * the login listeners and the WebDAV plugin each load only what they use.
 */
#[Group('DB')]
class FreshRequestCostTest extends IntegrationTestCase {
	private const UID = 'ids-fresh-request';
	private const NS = 'OCA\\IntrusionDetection\\';

	private ?IUser $user = null;

	protected function setUp(): void {
		parent::setUp();
		$this->user = Server::get(IUserManager::class)->createUser(self::UID, 'A-long-test-password-' . self::UID) ?: null;
	}

	protected function tearDown(): void {
		$this->user?->delete();
		parent::tearDown();
	}

	public function testAnAppPasswordRequestLoadsOnlyWhatItUses(): void {
		$result = $this->runFresh();

		$this->assertNotContains(self::NS . 'Listener\\LoginListener', $result['afterBoot'], 'registering the app loads no listener for its constants');
		$this->assertNotContains(self::NS . 'Listener\\AdminChangeListener', $result['afterBoot']);
		$this->assertNotContains(self::NS . 'Admin\\SetupProblems', $result['afterBoot']);

		$this->assertSame([self::NS . 'Config\\LexiconData'], array_values(array_diff($result['lexicon']['classes'], [self::NS . 'Config\\Lexicon'])), 'the lexicon needs its data only, not the parameter types or key names');

		$listeners = array_values(array_filter($result['firstLogin']['classes'], static fn (string $c): bool => str_starts_with($c, self::NS . 'Listener\\') && !str_starts_with($c, self::NS . 'Listener\\Login\\')));
		$this->assertSame([self::NS . 'Listener\\LoginListener'], $listeners, 'the login steps are the only other listener code');
		foreach (['Confirm\\LoginAssessment', 'Signal\\SignalDispatcher', 'Response\\PasswordChangeService', 'Notification\\LoginNotices'] as $service) {
			$this->assertNotContains(self::NS . $service, $result['firstLogin']['classes'], 'an app password needs no step-up, breach, password change or notice');
		}
		$this->assertNotContains(self::NS . 'KnownDevice\\KnownDevices', $result['firstLogin']['classes'], 'an app is no device');

		$this->assertSame([], $result['repeatedLogin']['classes']);
		$this->assertSame(2, $result['repeatedLogin']['queries'], 'without a memory cache a repeated login reads its two rows and writes nothing');

		$rules = array_values(array_filter($result['davPlugin']['classes'], static fn (string $c): bool => str_contains($c, '\\Rules\\') || str_ends_with($c, 'RequestTarget')));
		$this->assertSame([], $rules, 'a WebDAV request with nothing to check builds no rule');
		$this->assertLessThanOrEqual(1, $result['davPlugin']['queries'], 'only core\'s check that the account is enabled');

		$this->assertCount(1, Server::get(LoginHistoryMapper::class)->forUser(self::UID, 0));
		$this->assertSame(1, count(Server::get(LoginMapper::class)->distinctUidsForIp('4:203.0.113.71', 0, 100)) + count(Server::get(LoginMapper::class)->distinctUidsForIp('203.0.113.71', 0, 100)));
	}

	public function testAFailedLoginWithEveryCheckOffLoadsNoDetector(): void {
		foreach (array_keys(LexiconData::CHECKS) as $id) {
			$this->appConfig->setValueString(Application::APP_ID, Keys::mode($id), Mode::Off->value);
		}
		/** @var array{classes: list<string>, queries: int} $result */
		$result = $this->runFresh('failed-login.php');

		$detectors = array_values(array_filter($result['classes'], static fn (string $c): bool => str_ends_with($c, 'Detector')));
		$this->assertSame([], $detectors, 'a check that is off loads no detector');
		$this->assertLessThanOrEqual(44, count($result['classes']), implode("\n", $result['classes']));
		$this->assertLessThanOrEqual(2, $result['queries']);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function runFresh(string $fixture = 'login-request.php'): array {
		$script = dirname(__DIR__) . '/fixtures/fresh/' . $fixture;
		$process = proc_open([PHP_BINARY, $script, FreshRequestProbe::serverRoot(), self::UID], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($process);
		$output = (string)stream_get_contents($pipes[1]);
		$errors = (string)stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$this->assertSame(0, proc_close($process), $errors . $output);
		$json = substr($output, (int)strrpos($output, "\n") + 1);
		$result = json_decode($json, true);
		$this->assertIsArray($result, $output);
		return $result;
	}
}
