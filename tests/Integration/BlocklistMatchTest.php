<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCP\L10N\IFactory;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

#[Group('DB')]
class BlocklistMatchTest extends LoginFailureTestCase {
	private const PASSWORD = 'Sup3r-Secret-Passw0rd!';
	private const LOGIN = 'alice-secret-login';

	/** @var list<string> */
	private array $logLines = [];
	private bool $allowlisted = false;

	protected function setUp(): void {
		parent::setUp();
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->settingsEditor()->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'spamhaus_drop_v4', 'enabled' => true, 'mode' => 'observe'],
		]));
	}

	public function testAFailedLoginFromAListedAddressIsRecordedOncePerHour(): void {
		$this->requestContext->setVerdict(new Verdict(0, '', ['list:spamhaus_drop_v4', 'hosting'], time() + 300));
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);

		$detections = $this->detectionsOf(BlocklistMatch::ID);
		$this->assertCount(1, $detections, 'Merged per address and hour');
		$detection = $detections[0];
		$this->assertSame(2, $detection->getHits());
		$this->assertSame('198.51.100.7', $detection->getIp());
		$this->assertSame('low', $detection->getSeverity());
		$this->assertNull($detection->getUid(), 'The login name is not stored');
		$this->assertSame(['spamhaus_drop_v4'], $detection->getExplanationData()['facts']['lists']);

		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, $l);
		$this->assertStringContainsString('Spamhaus DROP (IPv4)', implode(' ', $narrative->happened));
	}

	public function testUnlistedAddressesAndAttributeListsAreNotRecorded(): void {
		$this->requestContext->setVerdict(new Verdict(0, '', ['hosting', 'tor'], time() + 300));
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);
		$this->assertSame([], $this->detectionsOf(BlocklistMatch::ID));
	}

	public function testNothingRunsWhileTheCheckIsOff(): void {
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Off);
		$this->requestContext->setVerdict(new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300));
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);
		$this->assertSame([], $this->detectionsOf(BlocklistMatch::ID));
	}

	public function testAllowlistedAddressesAreIgnored(): void {
		$this->allowlisted = true;
		$this->requestContext->setVerdict(new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300));
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);
		$this->assertSame([], $this->detectionsOf(BlocklistMatch::ID));
	}

	public function testTheLoginNameAndPasswordAreStoredAndLoggedNowhere(): void {
		$this->requestContext->setVerdict(new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300));
		$this->failLogin('198.51.100.7', self::LOGIN, self::PASSWORD);
		$this->assertCount(1, $this->detectionsOf(BlocklistMatch::ID));
		foreach (self::tables() as $table) {
			$qb = $this->db->getQueryBuilder();
			$result = $qb->select('*')->from($table)->executeQuery();
			$dump = json_encode($result->fetchAll());
			$result->closeCursor();
			$this->assertStringNotContainsString(self::PASSWORD, (string)$dump, $table);
			$this->assertStringNotContainsString(self::LOGIN, (string)$dump, $table);
		}
		foreach ($this->logLines as $line) {
			$this->assertStringNotContainsString(self::PASSWORD, $line);
			$this->assertStringNotContainsString(self::LOGIN, $line);
		}
	}

	protected function throttler(): IThrottler {
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (): bool => $this->allowlisted);
		return $throttler;
	}

	protected function listenerLogger(): LoggerInterface {
		$test = $this;
		return new class($test) extends AbstractLogger {
			public function __construct(
				private readonly BlocklistMatchTest $test,
			) {
			}

			public function log($level, \Stringable|string $message, array $context = []): void {
				$this->test->logged((string)$message . ' ' . json_encode($context));
			}
		};
	}

	public function logged(string $line): void {
		$this->logLines[] = $line;
	}
}
