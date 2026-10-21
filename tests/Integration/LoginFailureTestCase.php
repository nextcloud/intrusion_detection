<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\DecoyCredentialDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\ReservedNameDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\ICacheFactory;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Drives the failed-login listener with real AnyLoginFailedEvent objects,
 * from addresses the test chooses, against the real database.
 */
abstract class LoginFailureTestCase extends IntegrationTestCase {
	protected FailedLoginListener $listener;
	protected Settings $settings;
	protected DetectionMapper $detections;
	protected AttemptMapper $attempts;
	/** @var IRequest&MockObject */
	protected IRequest $request;
	protected string $remoteAddress = '198.51.100.7';
	protected string $userAgent = 'curl/8.0';
	/** @var list<string> */
	private array $createdUsers = [];

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->detections = Server::get(DetectionMapper::class);
		$this->attempts = Server::get(AttemptMapper::class);
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		$this->request->method('getHeader')->willReturnCallback(fn (string $name): string => $name === 'User-Agent' ? $this->userAgent : '');
		$addresses = new RemoteAddressResolver($this->request, Server::get(IThrottler::class), Server::get(ServerAddresses::class));
		$this->listener = new FailedLoginListener(
			$this->settings,
			$addresses,
			$this->attemptRecorder(),
			Server::get(DecoyCredentialDetector::class),
			Server::get(ReservedNameDetector::class),
			// Built per test, so the memory-cache state of one test cannot leak into the next.
			new CredentialStuffingDetector(
				$this->settings,
				$this->attempts,
				Server::get(ResponseEngine::class),
				Server::get(FlaggedSources::class),
				Server::get(BanService::class),
				$addresses,
				Server::get(ICacheFactory::class),
				Server::get(RiskScorer::class),
			),
			new PasswordSprayingDetector(
				$this->settings,
				$this->attempts,
				Server::get(ResponseEngine::class),
				Server::get(FlaggedSources::class),
				Server::get(Fingerprinter::class),
				Server::get(ICacheFactory::class),
				Server::get(PasswordSpraying::class),
				Server::get(RiskScorer::class),
			),
			Server::get(AccountUnderAttackDetector::class),
			Server::get(RiskScorer::class),
			Server::get(IUserManager::class),
			$this->request,
			$this->listenerLogger(),
			Server::get(FailedLoginStats::class),
			Server::get(\OCA\IntrusionDetection\Login\EmailAccounts::class),
		);
	}

	protected function tearDown(): void {
		foreach ($this->createdUsers as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		parent::tearDown();
	}

	protected function listenerLogger(): LoggerInterface {
		return Server::get(LoggerInterface::class);
	}

	protected function attemptRecorder(): AttemptRecorder {
		return Server::get(AttemptRecorder::class);
	}

	protected function failLogin(string $ip, string $loginName, #[\SensitiveParameter] ?string $password = 'wrong-password'): void {
		$this->remoteAddress = $ip;
		$this->listener->handle(new AnyLoginFailedEvent($loginName, $password));
	}

	protected function user(string $uid): IUser {
		$manager = Server::get(IUserManager::class);
		$user = $manager->get($uid) ?? $manager->createUser($uid, 'A-long-test-password-' . $uid);
		$this->assertInstanceOf(IUser::class, $user);
		$this->createdUsers[] = $uid;
		return $user;
	}

	/**
	 * Store an attempt directly, for numbers that would be slow to produce
	 * through the listener, or for attempts in the past.
	 */
	protected function storeAttempt(string $ip, string $loginName, ?string $uid = null, ?string $password = null, ?int $at = null, AttemptKind $kind = AttemptKind::PasswordLogin): void {
		$source = SourceKey::fromIp($ip);
		$fingerprinter = Server::get(Fingerprinter::class);
		$this->attempts->insert(
			$kind,
			$source->ipKey,
			$source->netKey,
			bin2hex($fingerprinter->name($loginName)),
			$uid,
			null,
			$password === null ? null : bin2hex($fingerprinter->password($password)),
			$at ?? time(),
		);
	}

	/**
	 * @return list<Detection>
	 */
	protected function detectionsOf(string $checkId): array {
		return $this->detections->findList(new DetectionFilter(checkIds: [$checkId], limit: 1000));
	}

	protected function rows(string $table): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from($table);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * @return list<array<string, mixed>>
	 */
	protected function allRows(string $table): array {
		$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		return $rows;
	}
}
