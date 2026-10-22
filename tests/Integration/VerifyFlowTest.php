<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The verify page (concept sections 11.5 and 15.2) with a login from a
 * flagged address: the code lifecycle, failures, refusals and where the
 * page continues to.
 */
#[Group('DB')]
class VerifyFlowTest extends StepUpTestCase {
	private IUser $alice;
	/** @var array{id: int, secret: string} */
	private array $token;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-verify', 'alice@example.com');
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testThePageShowsTheMaskedAddressAndNeverTheCode(): void {
		$this->pendingLogin();
		$response = $this->verifyController()->show('/index.php/apps/files/');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertSame('guest', $response->getRenderAs());
		$html = $response->render();
		$this->assertStringContainsString('a***@example.com', $html);
		$this->assertStringNotContainsString('alice@example.com', $html);
		$this->assertStringNotContainsString('482915', $html);
		$this->assertStringContainsString('name="requesttoken"', $html);
		$this->assertStringContainsString('autocomplete="one-time-code"', $html);
		$this->assertStringContainsString('the address or its network took part in an attack', $html);
		$this->assertStringNotContainsString('second-factor', $html, 'No second factor to offer');
	}

	public function testTheRightCodeContinuesToThePageTheUserWanted(): void {
		$this->pendingLogin();
		$response = $this->verifyController()->confirm('482 915', '/index.php/apps/files/?dir=/Photos');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith('/index.php/apps/files/?dir=/Photos', $response->getRedirectURL());
		$this->assertNull($this->stepUp());
		$this->assertSame('email_code', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null);
		$this->assertSame(0, $this->unconfirmedRows());
		$this->assertNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')), 'The session may continue');
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function unsafeTargets(): array {
		return [
			'another host' => ['https://evil.example/'],
			'protocol-relative' => ['//evil.example/'],
			'backslash' => ['/\\evil.example'],
			'the verify page' => ['/index.php/apps/intrusion_detection/verify'],
		];
	}

	#[DataProvider('unsafeTargets')]
	public function testOnlyLocalPathsAreContinuedTo(string $target): void {
		$this->pendingLogin();
		$response = $this->verifyController()->confirm('482915', $target);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame(Server::get(IURLGenerator::class)->linkToDefaultPageUrl(), $response->getRedirectURL());
		$this->assertStringNotContainsString('evil', (string)$this->verifyController()->show($target)->getHeaders()['Location']);
	}

	public function testAWrongCodeIsThrottledAndCounted(): void {
		$this->pendingLogin();
		$response = $this->verifyController()->confirm('000000');
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertTrue($response->isThrottled());
		$this->assertSame('This code is not correct. You can try 4 more times.', $this->paramOf($response, 'error'));
		$this->assertSame(1, $this->stepUp()?->attempts);
		$this->assertNotNull($this->sessionUser, 'Still waiting');
	}

	public function testFiveWrongCodesEndTheLoginAndBlockTheAddress(): void {
		$this->pendingLogin();
		for ($i = 0; $i < 4; $i++) {
			$this->verifyController()->confirm('000000');
		}
		$response = $this->verifyController()->confirm('000000');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringContainsString('/verify/ended?reason=attempts', $response->getRedirectURL());
		$this->assertTrue($response->isThrottled());

		$this->assertNull($this->sessionUser, 'Logged out');
		$this->assertFalse($this->tokenExists($this->token['id']), 'The session token is gone');
		$this->assertSame(0, $this->unconfirmedRows());
		$failed = $this->detectionsOf(StepUpFailed::ID);
		$this->assertCount(1, $failed);
		$this->assertSame('high', $failed[0]->getSeverity());
		$this->assertSame(StepUpFailed::RULE_ATTEMPTS, $failed[0]->getExplanationData()['facts']['rule']);
		$this->assertSame(['ban', 'kill_session', 'notify_admin', 'notify_user'], array_column($failed[0]->getActionList(), 'type'));
		$this->assertNotSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp($this->remoteAddress)->ipKey], time()), 'Blocked');
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT));
	}

	public function testParallelRequestsGetNoMoreThanFiveTriesBetweenThem(): void {
		$this->pendingLogin();
		// Every request read the session before any of them saved it.
		$loaded = $this->state->get(SessionState::STEP_UP);
		$this->assertNotNull($loaded);
		$statuses = [];
		foreach (['000000', '000000', '000000', '000000', '000000', '482915', '000000'] as $code) {
			$this->sessionUser = $this->alice;
			$this->state->set(SessionState::STEP_UP, $loaded);
			$response = $this->verifyController()->confirm($code);
			$statuses[] = $response instanceof RedirectResponse ? $response->getRedirectURL() : $response->getStatus();
		}
		$this->assertSame([Http::STATUS_FORBIDDEN, Http::STATUS_FORBIDDEN, Http::STATUS_FORBIDDEN, Http::STATUS_FORBIDDEN], array_slice($statuses, 0, 4));
		foreach (array_slice($statuses, 4) as $i => $status) {
			$this->assertIsString($status, 'Request ' . ($i + 5) . ' gets no try');
			$this->assertStringContainsString('/verify/ended?reason=attempts', $status);
		}
		$this->assertNull($this->state->get(SessionState::CONFIRMATION), 'Not even the right code got in');
		$this->assertCount(1, $this->detectionsOf(StepUpFailed::ID));
	}

	public function testANewLoginInTheSameSessionStartsWithFiveTries(): void {
		$this->pendingLogin();
		for ($i = 0; $i < 4; $i++) {
			$this->verifyController()->confirm('000000');
		}
		$this->login($this->alice);
		$this->assertSame(0, $this->stepUp()?->attempts);
		$response = $this->verifyController()->confirm('000000');
		$this->assertSame('This code is not correct. You can try 4 more times.', $this->paramOf($response, 'error'), 'The server counts afresh too');
	}

	public function testAfterFiveCodesInAnHourTheLoginWaitsWithoutANewOne(): void {
		Server::get(IUserConfig::class)->setValueArray($this->alice->getUID(), Application::APP_ID, UserKeys::CODE_MAILS, array_fill(0, EmailCodes::MAX_MAILS, time() - 60), lazy: true);
		$this->pendingLogin();
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $this->stepUp()?->methods, 'Still held: never let through for lack of a code');
		$this->assertNull($this->stepUp()?->codeHash);
		$this->assertSame([], $this->mailed);

		$page = $this->verifyController()->show();
		$this->assertStringContainsString('Too many codes were sent to your email address in the last hour', (string)$this->paramOf($page, 'error'));
		$this->assertFalse($this->paramOf($page, 'canResend'));
		$this->assertStringNotContainsString('We sent a 6-digit code', (string)$this->paramOf($page, 'lead'));
		$this->assertStringContainsString('Too many codes', (string)$this->paramOf($this->verifyController()->resend(), 'error'));
		$this->assertSame([], $this->mailed);
	}

	public function testALoginThatWaitsTooLongIsEndedWithoutBlockingTheAddress(): void {
		$this->pendingLogin();
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$expired = StepUpState::fromArray(array_merge($stepUp->toArray(), ['deadline' => time() - 1]));
		$this->assertNotNull($expired);
		$this->service()->save($expired);

		$block = $this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/'));
		$this->assertNotNull($block);
		$this->assertStringContainsString('reason=timeout', (string)$block->redirectUrl);
		$this->assertNull($this->sessionUser);
		$this->assertFalse($this->tokenExists($this->token['id']));
		$failed = $this->detectionsOf(StepUpFailed::ID)[0];
		$this->assertSame(StepUpFailed::RULE_TIMEOUT, $failed->getExplanationData()['facts']['rule']);
		$this->assertSame(['kill_session', 'notify_admin', 'notify_user'], array_column($failed->getActionList(), 'type'));
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp($this->remoteAddress)->ipKey], time()));
	}

	public function testAnExpiredCodeIsExplained(): void {
		$this->pendingLogin();
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$stepUp->codeExpires = time() - 1;
		$this->service()->save($stepUp);
		$response = $this->verifyController()->confirm('482915');
		$this->assertSame('This code has expired. Send a new one, then enter it.', $this->paramOf($response, 'error'));
		$this->assertSame(0, $this->stepUp()?->attempts);
	}

	public function testANewCodeCanBeSentThreeTimes(): void {
		$this->pendingLogin();
		for ($i = 0; $i < 3; $i++) {
			$response = $this->verifyController()->resend();
			$this->assertStringContainsString('A new code was sent to a***@example.com', (string)$this->paramOf($response, 'notice'));
		}
		$this->assertSame('650417', $this->lastCode($this->alice->getUID()));
		$response = $this->verifyController()->resend();
		$this->assertStringContainsString('No more codes can be sent', (string)$this->paramOf($response, 'error'));
		$this->assertFalse($this->paramOf($response, 'canResend'));
		$this->assertInstanceOf(RedirectResponse::class, $this->verifyController()->confirm('650417'), 'The newest code works');
	}

	public function testARefusedLoginIsToldWhyWithItsReferenceAndEnded(): void {
		$bob = $this->user('ids-verify-noemail', null);
		$this->token = $this->startSession($bob);
		$this->login($bob);
		$reference = $this->stepUp()?->reference;
		$this->assertNotNull($reference);

		$response = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$html = $response->render();
		$this->assertStringContainsString('Your account has no email address or second factor that could confirm it, so this login cannot continue.', $html);
		$this->assertSame(1, substr_count($html, 'This login needs extra confirmation'), 'The lead does not repeat the title');
		$this->assertMatchesRegularExpression('/Give your administrator this reference, so that they can see what happened:\s*<span class="ids-page__reference">' . preg_quote($reference, '/') . '</', $html);
		$this->assertNull($this->sessionUser, 'The refused session ends once it was told');
		$this->assertSame(0, $this->unconfirmedRows());
		$this->assertInstanceOf(RedirectResponse::class, $this->verifyController()->confirm('482915'), 'Nothing to confirm any more');
	}

	public function testTheEndedPageOnlySaysWhyWithAFixedText(): void {
		$response = $this->verifyController()->ended('<script>alert(1)</script>');
		$html = $response->render();
		$this->assertStringContainsString('This login was never confirmed', $html);
		$this->assertStringNotContainsString('<script>alert', $html);
		$this->assertStringContainsString('was not confirmed in time', $this->verifyController()->ended(StepUpFailed::RULE_TIMEOUT)->render());
	}

	public function testWithoutAPendingLoginThePageContinuesAtOnce(): void {
		$this->sessionUser = $this->alice;
		$this->assertInstanceOf(RedirectResponse::class, $this->verifyController()->show('/index.php/apps/files/'));
		$this->assertInstanceOf(RedirectResponse::class, $this->verifyController()->resend());
		$this->assertInstanceOf(RedirectResponse::class, $this->verifyController()->secondFactor());
	}

	public function testTheSecondFactorIsOfferedOnlyWhenTheLoginHadOne(): void {
		$this->pendingLogin();
		$this->hasSecondFactor = true;
		$this->assertFalse($this->paramOf($this->verifyController()->show(), 'secondFactor'), 'A second factor set up during the pending login proves nothing');
		$this->verifyController()->secondFactor();
		$this->assertFalse($this->stepUp()?->secondFactorRequested);

		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$stepUp->methods = [IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE];
		$this->service()->save($stepUp);
		$this->assertTrue($this->paramOf($this->verifyController()->show(), 'secondFactor'));

		$this->passChallenge($this->alice);
		$this->assertNotNull($this->stepUp(), 'Not asked for: a challenge passed for something else does not count');

		$response = $this->verifyController()->secondFactor('/index.php/apps/files/');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame('/index.php/login/challenge?redirect_url=back', $response->getRedirectURL());
		$this->passChallenge($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertSame('second_factor', $this->state->get(SessionState::CONFIRMATION)['by'] ?? null);
	}

	public function testTheEndpointsAreProtected(): void {
		$class = new \ReflectionClass(VerifyController::class);
		foreach (['confirm', 'resend', 'secondFactor'] as $method) {
			$reflection = $class->getMethod($method);
			$this->assertSame([], $reflection->getAttributes(NoCSRFRequired::class), $method . ' is CSRF-protected');
			$this->assertNotSame([], $reflection->getAttributes(UserRateLimit::class), $method . ' is rate limited');
		}
		$this->assertNotSame([], $class->getMethod('confirm')->getAttributes(BruteForceProtection::class));
		foreach ($class->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			$this->assertSame([], $method->getAttributes(\OCP\AppFramework\Http\Attribute\NoTwoFactorRequired::class), $method->getName() . ': a waiting second factor comes first');
			if ($method->getName() !== 'ended') {
				$this->assertSame([], $method->getAttributes(PublicPage::class), $method->getName());
			}
		}
	}

	public function testTheTimeLimits(): void {
		$this->pendingLogin();
		$stepUp = $this->stepUp();
		$this->assertSame(StepUpService::SESSION_TTL, ($stepUp?->deadline ?? 0) - ($stepUp?->started ?? 0));
		$this->assertLessThanOrEqual(Server::get(ITimeFactory::class)->getTime() + EmailCodes::TTL, $stepUp?->codeExpires);
	}

	private function pendingLogin(): void {
		$this->token = $this->startSession($this->alice);
		$this->login($this->alice);
		$this->assertSame(StepUpState::PENDING, $this->stepUp()?->status);
	}

	private function paramOf(Response $response, string $name): mixed {
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		return $response->getParams()[$name] ?? null;
	}
}
