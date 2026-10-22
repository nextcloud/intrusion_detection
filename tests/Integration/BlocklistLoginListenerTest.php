<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Listener\BlocklistLoginListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\IRequest;
use OCP\L10N\IFactory;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\AbstractLogger;

#[Group('DB')]
class BlocklistLoginListenerTest extends IntegrationTestCase {
	private const PASSWORD = 'Sup3r-Secret-Passw0rd!';
	private const LOGIN = 'alice-secret-login';

	/** @var list<string> */
	private array $logLines = [];

	protected function setUp(): void {
		parent::setUp();
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->settingsEditor()->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'spamhaus_drop_v4', 'enabled' => true, 'mode' => 'observe'],
		]));
	}

	public function testAFailedLoginFromAListedAddressIsRecordedOncePerHour(): void {
		$listener = $this->listener('198.51.100.7', new Verdict(0, '', ['list:spamhaus_drop_v4', 'hosting'], time() + 300));
		$listener->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));
		$listener->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));

		$detections = Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [BlocklistMatch::ID]));
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
		$this->listener('198.51.100.7', new Verdict(0, '', ['hosting', 'tor'], time() + 300))->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));
		$this->assertSame(0, $this->countDetections());
	}

	public function testNothingRunsWhileTheCheckIsOff(): void {
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Off);
		$this->listener('198.51.100.7', new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300))->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));
		$this->assertSame(0, $this->countDetections());
	}

	public function testAllowlistedAddressesAreIgnored(): void {
		$this->listener('198.51.100.7', new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300), allowlisted: true)
			->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));
		$this->assertSame(0, $this->countDetections());
	}

	public function testTheLoginNameAndPasswordAreStoredAndLoggedNowhere(): void {
		$this->listener('198.51.100.7', new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300))->handle(new AnyLoginFailedEvent(self::LOGIN, self::PASSWORD));
		$this->assertSame(1, $this->countDetections());
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

	private function countDetections(): int {
		$qb = $this->db->getQueryBuilder();
		$result = $qb->select($qb->func()->count('*'))->from('ids_detections')->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	private function listener(string $ip, Verdict $verdict, bool $allowlisted = false): BlocklistLoginListener {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn($ip);
		$request->method('getHeader')->willReturn('curl/8.0');
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturn($allowlisted);
		$context = new RequestContext();
		$context->setVerdict($verdict);
		$test = $this;
		$logger = new class($test) extends AbstractLogger {
			public function __construct(
				private readonly BlocklistLoginListenerTest $test,
			) {
			}

			public function log($level, \Stringable|string $message, array $context = []): void {
				$this->test->logged((string)$message . ' ' . json_encode($context));
			}
		};
		return new BlocklistLoginListener(
			$this->checkSettings(),
			new RemoteAddressResolver($request, $throttler, Server::get(ServerAddresses::class)),
			$context,
			Server::get(AddressCache::class),
			Server::get(CheckRegistry::class),
			Server::get(SourceRepository::class),
			Server::get(ResponseEngine::class),
			$request,
			$logger,
		);
	}

	public function logged(string $line): void {
		$this->logLines[] = $line;
	}
}
