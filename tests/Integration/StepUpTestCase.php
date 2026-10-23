<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Confirm\AccountMethods;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\FamiliarLogin;
use OCA\IntrusionDetection\Confirm\LoginAssessment;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\Confirm\LoginConfirmationStore;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\EmailCodeMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\PendingLoginFlow;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\KnownDevice\DeviceCookie;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\ChallengePassedListener;
use OCA\IntrusionDetection\Listener\Login\HistoryStep;
use OCA\IntrusionDetection\Listener\Login\ILoginStep;
use OCA\IntrusionDetection\Listener\Login\KnownDeviceStep;
use OCA\IntrusionDetection\Listener\Login\StepUpStep;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Login\SessionTokenLinker;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCA\IntrusionDetection\Tests\LoginSteps;
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
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\IHasher;
use OCP\Security\ISecureRandom;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
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
	protected SessionMarkers $state;
	/** @var IChallengeRequester&MockObject */
	protected IChallengeRequester $challenges;
	/** @var list<array{string, int}> device cookies set: value and expiry */
	protected array $deviceCookiesSet = [];
	private ?KnownDevices $knownDevices = null;
	private ?LoginHistory $history = null;

	protected function setUp(): void {
		parent::setUp();
		$this->state = new SessionMarkers($this->session, Server::get(LoggerInterface::class));
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

	/**
	 * The login listener with the step-up step only, as the other tests of
	 * the step-up need it.
	 */
	protected function listener(): LoginListener {
		return $this->loginListener([StepUpStep::class]);
	}

	/**
	 * A login through the app: the step-up, the known device and the login history.
	 */
	protected function loginThroughTheApp(IUser $user, UserLoggedInEvent|UserLoggedInWithCookieEvent|null $event = null): void {
		$event ??= new UserLoggedInEvent($user, $user->getUID(), self::PASSWORD, false);
		if ($this->session->id === null) {
			$this->session->id = bin2hex(random_bytes(32));
		}
		$this->sessionUser = $user;
		$this->loginListener([StepUpStep::class, KnownDeviceStep::class, HistoryStep::class])->handle($event);
	}

	/**
	 * The app's login listener, running these of its steps, wired with the
	 * test session and request.
	 *
	 * @param list<class-string<ILoginStep>> $steps
	 */
	protected function loginListener(array $steps, ?LoginHistory $history = null): LoginListener {
		$context = new RequestContext();
		$services = [
			StepUpStep::class => new StepUpStep($this->assessment()),
			KnownDeviceStep::class => new KnownDeviceStep($this->knownDevices(), $this->service()),
			HistoryStep::class => new HistoryStep($history ?? $this->history()),
		];
		$steps = array_map(fn (string $class): ILoginStep => $services[$class] ?? Server::get($class), array_combine($steps, $steps));
		return LoginSteps::listener($steps, $this->appSettings(), $this->request, $context, $this->addresses(), new LoginGate($this->listenerCaches ?? $this->noCaches(), $this->coreSession));
	}

	protected function assessment(): LoginAssessment {
		return new LoginAssessment(
			Server::get(Fingerprinter::class),
			Server::get(FlaggedSources::class),
			$this->stepUpReasons(),
			Server::get(UnconfirmedSessions::class),
			$this->coreSession,
			$this->request,
			new OverridingContainer([
				LoginConfirmations::class => $this->service(),
				LoginDetections::class => $this->linker(),
				SignalDispatcher::class => $this->dispatcher($this->listenerServices(), $this->engine()),
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
	 * The detectors of the login signals a test replaces.
	 *
	 * @return array<string, object>
	 */
	protected function listenerServices(): array {
		return [];
	}

	protected function service(): LoginConfirmations {
		return new LoginConfirmations(
			$this->store(),
			$this->userSession,
			$this->policy(),
			$this->engine(),
			$this->coreSession,
			$this->addresses(),
			Server::get(ITimeFactory::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
			$this->history(),
			new FamiliarLogin($this->knownDevices(), $this->history(), Server::get(TrustedNetworks::class), Server::get(ITimeFactory::class)),
			$this->request,
		);
	}

	protected function store(): LoginConfirmationStore {
		return new LoginConfirmationStore($this->state, Server::get(UnconfirmedSessions::class), $this->coreSession);
	}

	protected function policy(): ConfirmationPolicy {
		return new ConfirmationPolicy($this->appSettings(), new OverridingContainer([
			SecondFactorMethod::class => $this->secondFactorMethod(),
			KnownDeviceMethod::class => new KnownDeviceMethod($this->knownDevices(), $this->appSettings()),
			EmailCodeMethod::class => new EmailCodeMethod($this->codes(), $this->accountMethods()),
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
			$this->coreSession,
			new SessionTokenLinker($this->state, $this->coreSession),
			Server::get(ITimeFactory::class),
			$this->appSettings(),
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

	/**
	 * What the accounts can confirm with: email as the server sends it, the
	 * second factor as the test says.
	 */
	protected function accountMethods(): AccountMethods {
		return new AccountMethods(Server::get(MailReach::class), $this->secondFactors());
	}

	protected function secondFactors(): SecondFactors {
		return new SecondFactors($this->registry(), Server::get(ProviderLoader::class), $this->untrustedSecondFactors(), Server::get(LoggerInterface::class));
	}

	protected function codes(): EmailCodes {
		$random = $this->createMock(ISecureRandom::class);
		$random->method('generate')->willReturnCallback(fn (): string => array_shift($this->codes) ?? '999999');
		return new EmailCodes(
			$random,
			Server::get(IHasher::class),
			$this->mails,
			Server::get(UserMessages::class),
			Server::get(ITimeFactory::class),
			$this->store(),
			Server::get(IUserConfig::class),
		);
	}

	protected function linker(): LoginDetections {
		return new LoginDetections($this->state, Server::get(DetectionMapper::class), new SessionTokenLinker($this->state, $this->coreSession), Server::get(LoggerInterface::class));
	}

	protected function rule(): StepUpRule {
		$setup = $this->createMock(SecondFactorSetup::class);
		$setup->method('isRequired')->willReturnCallback(fn (): bool => $this->secondFactorSetupRequired);
		return new StepUpRule($this->userSession, Server::get(IURLGenerator::class), Server::get(ITimeFactory::class), new OverridingContainer([
			LoginConfirmations::class => $this->service(),
			LoginDetections::class => $this->linker(),
			SecondFactorSetup::class => $setup,
		]), Server::get(LoggerInterface::class));
	}

	protected function sessionConfirmation(): SessionConfirmation {
		return new SessionConfirmation($this->store(), $this->coreSession);
	}

	protected function untrustedSecondFactors(): UntrustedSecondFactors {
		return new UntrustedSecondFactors(Server::get(IUserConfig::class), $this->userSession, $this->sessionConfirmation(), Server::get(ITimeFactory::class));
	}

	protected function secondFactorMethod(): SecondFactorMethod {
		return new SecondFactorMethod($this->challenges, $this->accountMethods());
	}

	/**
	 * Core reports a passed challenge of the session.
	 */
	protected function passChallenge(IUser $user, string $providerId = 'totp'): void {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn($providerId);
		(new ChallengePassedListener($this->service(), $this->secondFactors(), $this->history(), $this->appSettings(), Server::get(LoggerInterface::class)))
			->handle(new TwoFactorProviderChallengePassed($user, $provider));
	}

	protected function verifyController(): VerifyController {
		return new VerifyController(
			$this->request,
			$this->userSession,
			new PendingLoginFlow($this->service(), $this->policy(), $this->codes(), $this->knownDevices(), $this->addresses(), $this->request),
			$this->codes(),
			Server::get(IURLGenerator::class),
			Server::get(LocalRedirect::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->knownDevices(),
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
