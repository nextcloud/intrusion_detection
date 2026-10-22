<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\FamiliarLogin;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\DeviceCookie;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\StepUpChallengePassedListener;
use OCA\IntrusionDetection\Listener\StepUpLoginListener;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IChallengeRequester;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\Config\IUserConfig;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Mail\IEmailValidator;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Logins that need extra confirmation, wired like the app wires them, with
 * the test session, a request whose address and headers the test chooses,
 * captured emails and a known sequence of email codes.
 */
abstract class StepUpTestCase extends AccountTestCase {
	use BasicAuthServer;

	public const PASSWORD = 'Correct-Horse-Battery-Staple-2026';

	protected string $remoteAddress = '198.51.100.7';
	/** @var array<string, string> */
	protected array $headers = [];
	/** @var array<string, string> */
	protected array $cookies = [];
	protected string $method = 'POST';
	protected string $pathInfo = '/login';
	/** @var list<string> */
	protected array $codes = ['482915', '730264', '119838', '650417', '004213', '871102'];
	protected bool $hasSecondFactor = false;
	/** Whether core holds the login at the setup of a second factor */
	protected bool $secondFactorSetupRequired = false;
	/** The memory caches of the login listener; none by default */
	protected ?Caches $listenerCaches = null;
	protected bool $bypassListed = false;
	/** @var IRequest&MockObject */
	protected IRequest $request;
	protected SessionState $state;
	/** @var IChallengeRequester&MockObject */
	protected IChallengeRequester $challenges;
	/** @var list<array{string, int}> device cookies set: value and expiry */
	protected array $deviceCookiesSet = [];
	private ?KnownDevices $knownDevices = null;
	private ?LoginHistory $history = null;

	protected function setUp(): void {
		parent::setUp();
		$this->state = new SessionState($this->session, Server::get(LoggerInterface::class));
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		$this->request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		$this->request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$this->request->method('getPathInfo')->willReturnCallback(fn (): string => $this->pathInfo);
		$this->request->method('getCookie')->willReturnCallback(fn (string $name): ?string => $this->cookies[$name] ?? null);
		$this->request->method('getRequestUri')->willReturn('/index.php/apps/files/');
		$this->userSession->method('logout')->willReturnCallback(function (): void {
			$this->sessionUser = null;
			$this->session->clear();
		});
		$this->challenges = $this->createMock(IChallengeRequester::class);
		$this->challenges->method('isAvailable')->willReturnCallback(fn (): bool => $this->hasSecondFactor);
		$this->challenges->method('requestChallenge')->willReturn('/index.php/login/challenge?redirect_url=back');
	}

	/**
	 * A password login through the login form (or, with Basic auth headers,
	 * from an app), as core reports it.
	 */
	protected function login(IUser $user, string $password = self::PASSWORD, bool $tokenLogin = false): void {
		if ($this->session->id === null) {
			$this->session->id = bin2hex(random_bytes(32));
		}
		$this->sessionUser = $user;
		$this->listener()->handle(new UserLoggedInEvent($user, $user->getUID(), $password, $tokenLogin));
	}

	protected function basicAuth(IUser $user, string $password = self::PASSWORD): void {
		$this->headers['Authorization'] = 'Basic ' . base64_encode($user->getUID() . ':' . $password);
		$this->setBasicCredentials($user->getUID(), $password);
		$this->method = 'PROPFIND';
		$this->pathInfo = '/files/' . $user->getUID();
	}

	protected function user(string $prefix, ?string $email = 'person@example.com'): IUser {
		$user = $this->newUser($prefix, $email);
		$user->setPassword(self::PASSWORD);
		return $user;
	}

	protected function stepUp(): ?StepUpState {
		return $this->service()->current();
	}

	protected function listener(): StepUpLoginListener {
		return new StepUpLoginListener(
			$this->appSettings(), $this->checkSettings(),
			new InteractiveLogin($this->request),
			$this->addresses(),
			Server::get(Fingerprinter::class),
			Server::get(FlaggedSources::class),
			$this->stepUpReasons(),
			Server::get(UnconfirmedSessions::class),
			$this->request,
			$this->session,
			new OverridingContainer($this->listenerServices() + [
				StepUpService::class => $this->service(),
				LoginDetections::class => $this->linker(),
				PasswordSprayingDetector::class => new PasswordSprayingDetector(
					$this->checkSettings(),
					Server::get(AttemptMapper::class),
					$this->engine(),
					Server::get(FlaggedSources::class),
					Server::get(Fingerprinter::class),
					Server::get(Caches::class),
					Server::get(PasswordSpraying::class),
					Server::get(RiskScorer::class),
				),
			]),
			$this->listenerCaches ?? $this->noCaches(),
			Server::get(LoggerInterface::class),
		);
	}

	protected function noCaches(): Caches {
		return FixedCaches::none();
	}

	/**
	 * The reasons the login listener collects.
	 */
	protected function stepUpReasons(): StepUpReasons {
		return Server::get(StepUpReasons::class);
	}

	/**
	 * Further services of the login listener a test replaces.
	 *
	 * @return array<string, object>
	 */
	protected function listenerServices(): array {
		return [];
	}

	protected function service(): StepUpService {
		return new StepUpService(
			$this->state,
			$this->session,
			$this->userSession,
			$this->policy(),
			$this->engine(),
			$this->checkSettings(),
			Server::get(UnconfirmedSessions::class),
			$this->currentSession,
			$this->addresses(),
			Server::get(StepUpFailed::class),
			Server::get(StepUpUnconfirmed::class),
			Server::get(ITimeFactory::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
			$this->history(),
			new FamiliarLogin($this->knownDevices(), Server::get(LoginHistoryMapper::class), Server::get(TrustedNetworks::class), Server::get(ITimeFactory::class)),
			$this->request,
		);
	}

	protected function policy(): ConfirmationPolicy {
		return new ConfirmationPolicy($this->appSettings(), new OverridingContainer([
			SecondFactorMethod::class => $this->secondFactorMethod(),
			KnownDeviceMethod::class => new KnownDeviceMethod($this->knownDevices(), $this->appSettings()),
			EmailCodeMethod::class => new EmailCodeMethod($this->codes()),
			AdminApprovalMethod::class => new AdminApprovalMethod(
				Server::get(ApprovalService::class),
				Server::get(ApprovalMapper::class),
				Server::get(Approvers::class),
				$this->appSettings(),
				Server::get(ITimeFactory::class),
			),
		]), Server::get(LoggerInterface::class));
	}

	/**
	 * The known devices of the test request: its cookies are $this->cookies,
	 * and cookies set are recorded there and in $this->deviceCookiesSet.
	 */
	protected function knownDevices(): KnownDevices {
		if ($this->knownDevices === null) {
			$cookie = new class($this->request, Server::get(IConfig::class), Server::get(IURLGenerator::class), Server::get(ISecureRandom::class), $this->setDeviceCookie(...)) extends DeviceCookie {
				/** @param \Closure(string, int): void $sink */
				public function __construct(
					IRequest $request,
					IConfig $config,
					IURLGenerator $urlGenerator,
					ISecureRandom $random,
					private \Closure $sink,
				) {
					parent::__construct($request, $config, $urlGenerator, $random);
				}

				#[\Override]
				protected function send(#[\SensitiveParameter] string $value, int $expires): bool {
					($this->sink)($value, $expires);
					return true;
				}
			};
			$this->knownDevices = new KnownDevices(
				Server::get(KnownDeviceMapper::class),
				$cookie,
				Server::get(Fingerprinter::class),
				$this->appSettings(),
				Server::get(ITimeFactory::class),
				Server::get(AuditLogger::class),
			);
		}
		return $this->knownDevices;
	}

	protected function history(): LoginHistory {
		return $this->history ??= new LoginHistory(
			Server::get(LoginHistoryMapper::class),
			$this->state,
			$this->currentSession,
			new LoginGate(Server::get(Caches::class), $this->session),
			Server::get(ITimeFactory::class),
		);
	}

	/**
	 * The next request: services that remember things for one request start afresh.
	 */
	protected function nextRequest(): void {
		$this->knownDevices = null;
	}

	protected function deviceCookieName(): string {
		return DeviceCookie::PREFIX . preg_replace('/[^a-z0-9]/i', '', Server::get(IConfig::class)->getSystemValueString('instanceid'));
	}

	private function setDeviceCookie(string $value, int $expires): void {
		$this->deviceCookiesSet[] = [$value, $expires];
		if ($expires > time()) {
			$this->cookies[$this->deviceCookieName()] = $value;
		} else {
			unset($this->cookies[$this->deviceCookieName()]);
		}
	}

	protected function codes(): EmailCodes {
		$random = $this->createMock(ISecureRandom::class);
		$random->method('generate')->willReturnCallback(fn (): string => array_shift($this->codes) ?? '999999');
		return new EmailCodes(
			$random,
			Server::get(IHasher::class),
			$this->mails,
			Server::get(UserMessages::class),
			Server::get(IEmailValidator::class),
			Server::get(IConfig::class),
			Server::get(ITimeFactory::class),
			Server::get(UnconfirmedSessions::class),
			$this->session,
			Server::get(IUserConfig::class),
		);
	}

	protected function linker(): LoginDetections {
		return new LoginDetections($this->state, Server::get(DetectionMapper::class), $this->currentSession, Server::get(LoggerInterface::class));
	}

	protected function rule(): StepUpRule {
		$setup = $this->createMock(SecondFactorSetup::class);
		$setup->method('isRequired')->willReturnCallback(fn (): bool => $this->secondFactorSetupRequired);
		return new StepUpRule($this->userSession, Server::get(IURLGenerator::class), Server::get(ITimeFactory::class), new OverridingContainer([
			StepUpService::class => $this->service(),
			LoginDetections::class => $this->linker(),
			SecondFactorSetup::class => $setup,
		]), Server::get(LoggerInterface::class));
	}

	protected function sessionConfirmation(): SessionConfirmation {
		return new SessionConfirmation($this->state, $this->session, Server::get(ITimeFactory::class));
	}

	protected function untrustedSecondFactors(): UntrustedSecondFactors {
		return new UntrustedSecondFactors(Server::get(IUserConfig::class), $this->userSession, $this->sessionConfirmation(), Server::get(ITimeFactory::class));
	}

	protected function secondFactorMethod(): SecondFactorMethod {
		return new SecondFactorMethod($this->challenges, $this->registry(), $this->untrustedSecondFactors());
	}

	/**
	 * Core reports a passed challenge of the session.
	 */
	protected function passChallenge(IUser $user, string $providerId = 'totp'): void {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn($providerId);
		(new StepUpChallengePassedListener($this->service(), $this->secondFactorMethod(), $this->sessionConfirmation(), Server::get(LoggerInterface::class)))
			->handle(new TwoFactorProviderChallengePassed($user, $provider));
	}

	protected function verifyController(): VerifyController {
		return new VerifyController(
			$this->request,
			$this->userSession,
			$this->service(),
			$this->codes(),
			$this->policy(),
			Server::get(IURLGenerator::class),
			Server::get(LocalRedirect::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->knownDevices(),
			$this->addresses(),
			Server::get(ITimeFactory::class),
		);
	}

	protected function addresses(): RemoteAddressResolver {
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (): bool => $this->bypassListed);
		return new RemoteAddressResolver($this->request, $throttler, Server::get(ServerAddresses::class));
	}

	/**
	 * The code in the last email to the account.
	 */
	protected function lastCode(string $uid): ?string {
		foreach (array_reverse($this->mailed) as [$to, $mail]) {
			if ($to === $uid && $mail->templateId === 'intrusion_detection.stepUpCode') {
				if (preg_match('/(\d{6})$/', $mail->heading, $match) === 1) {
					return $match[1];
				}
			}
		}
		return null;
	}

	/**
	 * @return list<Detection>
	 */
	protected function detectionsOf(string $checkId): array {
		return Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [$checkId], limit: 100));
	}

	protected function unconfirmedRows(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from(StepUpSessionMapper::TABLE);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	private function registry(): IRegistry {
		$registry = $this->createMock(IRegistry::class);
		$registry->method('getProviderStates')->willReturnCallback(fn (): array => $this->hasSecondFactor ? ['totp' => true] : []);
		return $registry;
	}
}
