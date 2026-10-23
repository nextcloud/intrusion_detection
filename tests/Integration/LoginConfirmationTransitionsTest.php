<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\AbandonedLogins;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IUser;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Every change of a login's confirmation and what it leaves behind: the
 * session's markers, the remembered session on the server, the login
 * history, the detections, and whether the session goes on.
 */
#[Group('DB')]
class LoginConfirmationTransitionsTest extends StepUpTestCase {
	private IUser $alice;
	private IUser $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-transitions', 'alice@example.com');
		$this->bob = $this->user('ids-transitions-bob', null);
	}

	public function testALoginWithoutAReason(): void {
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(history: [null, 'none']), $this->snapshot($this->alice));
	}

	public function testALoginThatWaitsForTheEmailCode(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(stepUp: 'pending', rows: ['waiting'], history: ['pending', 'none']), $this->snapshot($this->alice));
	}

	public function testALoginThatWaitsForCoresSecondFactor(): void {
		$this->flagSource();
		$this->hasSecondFactor = true;
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(stepUp: 'pending', rows: ['waiting'], history: ['pending', 'none']), $this->snapshot($this->alice));
		$this->assertSame(['second_factor'], $this->stepUp()?->methods);
	}

	public function testARefusedLogin(): void {
		$this->flagSource();
		$this->startSession($this->bob);
		$this->loginThroughTheApp($this->bob);
		$this->assertSame($this->expected(stepUp: 'refused', rows: ['kept'], history: ['refused', 'none'], detections: ['step_up_refused']), $this->snapshot($this->bob));
	}

	public function testARefusedAppWithCoresCookieTestIsRemembered(): void {
		$this->flagSource();
		$this->basicAuth($this->alice);
		$this->cookies[StepUpService::COOKIE_TEST] = 'test';
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(stepUp: 'refused_client', rows: ['kept'], history: ['refused', 'none'], detections: ['step_up_refused_client']), $this->snapshot($this->alice));
	}

	public function testARefusedAppWithoutCoresCookieTestIsNotRemembered(): void {
		$this->flagSource();
		$this->basicAuth($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(stepUp: 'refused_client', history: ['refused', 'none'], detections: ['step_up_refused_client']), $this->snapshot($this->alice));
	}

	public function testALoginLetInWithoutAConfirmation(): void {
		$this->flagSource();
		$this->settingsEditor()->setGlobal(StepUpPolicy::FlaggedSource->settingKey(), 'allow_notify');
		$this->startSession($this->bob);
		$this->loginThroughTheApp($this->bob);
		$this->assertSame($this->expected(confirmation: ['none', false], history: ['allowed', 'none'], detections: ['step_up_unconfirmed']), $this->snapshot($this->bob));
		$this->assertSame(SessionConfirmation::UNCONFIRMED, $this->sessionConfirmation()->level($this->bob->getUID()));
	}

	public function testAnAppLetInWithoutAConfirmation(): void {
		Server::get(AccountProtection::class)->protect($this->bob->getUID(), time() + 3600);
		$this->basicAuth($this->bob);
		$this->loginThroughTheApp($this->bob);
		$this->assertSame($this->expected(confirmation: ['none', true], history: ['allowed', 'none'], detections: ['step_up_unconfirmed']), $this->snapshot($this->bob));
	}

	public function testALoginConfirmedByAKnownDevice(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->verifyController()->confirm('482915', '', '1');

		$this->session->clear();
		$this->nextRequest();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(confirmation: ['known_device', false], proof: 'known_device', history: ['confirmed', 'known_device']), $this->snapshot($this->alice));
		$this->assertSame(SessionConfirmation::PROVEN, $this->sessionConfirmation()->level($this->alice->getUID()));
	}

	public function testANormalLoginFromAKnownDeviceProvesTheDevice(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->verifyController()->confirm('482915', '', '1');

		Server::get(FlaggedSources::class)->unflagSource(SourceKey::fromIp($this->remoteAddress));
		$this->session->clear();
		$this->nextRequest();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->assertSame($this->expected(proof: 'known_device', history: [null, 'none']), $this->snapshot($this->alice));
		$this->assertSame(SessionConfirmation::PROVEN, $this->sessionConfirmation()->level($this->alice->getUID()));
	}

	public function testConfirmedWithTheEmailCode(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->verifyController()->confirm('482915');
		$this->assertSame($this->expected(confirmation: ['email_code', false], history: ['confirmed', 'email_code']), $this->snapshot($this->alice));
	}

	public function testConfirmedWithTheSecondFactor(): void {
		$this->flagSource();
		$this->hasSecondFactor = true;
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->passChallenge($this->alice);
		$this->assertSame($this->expected(confirmation: ['second_factor', false], history: ['confirmed', 'second_factor']), $this->snapshot($this->alice));
	}

	public function testASecondFactorWithoutAReasonIsAProof(): void {
		$this->hasSecondFactor = true;
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->passChallenge($this->alice);
		$this->assertSame($this->expected(proof: 'second_factor', history: [null, 'second_factor']), $this->snapshot($this->alice));
	}

	public function testConfirmedByAnAdministrator(): void {
		$this->waitForAnAdministrator();
		Server::get(ApprovalService::class)->approve((int)$this->stepUp()?->approvalId, 'admin', ApprovalService::VIA_WEB);
		$this->verifyController()->continueApproval();
		$this->assertSame($this->expected(confirmation: ['admin_approval', false], history: ['confirmed', 'admin_approval']), $this->snapshot($this->bob));
	}

	public function testFailedWithWrongCodes(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		for ($i = 0; $i < 5; $i++) {
			$this->verifyController()->confirm('111111');
		}
		$this->assertSame($this->expected(history: ['failed', 'none'], detections: ['step_up_failed:attempts'], loggedIn: false), $this->snapshot($this->alice));
	}

	public function testFailedWhenNotConfirmedInTime(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$marker = $this->state->get(SessionMarkers::STEP_UP) ?? [];
		$this->state->set(SessionMarkers::STEP_UP, ['deadline' => time() - 1] + $marker);
		$this->assertNotNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')));
		$this->assertSame($this->expected(history: ['failed', 'none'], detections: ['step_up_failed:timeout'], loggedIn: false), $this->snapshot($this->alice));
	}

	public function testFailedWhenAnAdministratorRejected(): void {
		$this->waitForAnAdministrator();
		Server::get(ApprovalService::class)->reject((int)$this->stepUp()?->approvalId, 'admin', ApprovalService::VIA_WEB);
		$this->verifyController()->continueApproval();
		$this->assertSame($this->expected(history: ['failed', 'none'], detections: ['step_up_failed:rejected'], loggedIn: false), $this->snapshot($this->bob));
	}

	public function testGivenUpWhileWaitingForAnAdministrator(): void {
		$this->waitForAnAdministrator();
		$this->verifyController()->cancelApproval();
		$this->assertSame($this->expected(history: ['failed', 'none'], loggedIn: false), $this->snapshot($this->bob));
	}

	public function testARefusedLoginEndsOnceItWasShownWhy(): void {
		$this->flagSource();
		$this->startSession($this->bob);
		$this->loginThroughTheApp($this->bob);
		$this->verifyController()->show();
		$this->assertSame($this->expected(history: ['refused', 'none'], detections: ['step_up_refused'], loggedIn: false), $this->snapshot($this->bob));
	}

	public function testAnUnconfirmedLoginThatComesBackThroughItsRememberMeCookie(): void {
		$this->flagSource();
		$this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$old = (string)$this->session->id;
		$this->session->clear();
		$this->session->id = bin2hex(random_bytes(32));
		$this->cookies['nc_session_id'] = $old;
		$this->method = 'GET';
		$this->loginThroughTheApp($this->alice, new UserLoggedInWithCookieEvent($this->alice, $this->alice->getUID(), null));
		$this->assertSame($this->expected(stepUp: 'resumed', rows: ['kept'], history: ['failed', 'none']), $this->snapshot($this->alice));

		$this->assertNotNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')));
		$this->assertSame($this->expected(history: ['failed', 'none'], detections: ['step_up_failed:resumed'], loggedIn: false), $this->snapshot($this->alice));
	}

	public function testAnUnconfirmedLoginThatComesBackFromItsSessionToken(): void {
		$this->flagSource();
		$token = $this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$this->session->clear();
		$this->session->id = $token['secret'];
		$this->method = 'GET';
		$this->loginThroughTheApp($this->alice, new UserLoggedInEvent($this->alice, $this->alice->getUID(), self::PASSWORD, true));
		$this->assertSame($this->expected(stepUp: 'resumed', rows: ['kept'], history: ['pending', 'none']), $this->snapshot($this->alice));

		$this->assertNotNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')));
		$this->assertSame($this->expected(history: ['pending', 'none'], detections: ['step_up_failed:resumed'], loggedIn: false), $this->snapshot($this->alice), 'The row was never linked to the session token, so it is not found');
	}

	public function testALoginLeftWaitingIsEndedByTheBackgroundJob(): void {
		$this->flagSource();
		$token = $this->startSession($this->alice);
		$this->loginThroughTheApp($this->alice);
		$qb = $this->db->getQueryBuilder();
		$qb->update(StepUpSessionMapper::TABLE)->set('deadline', $qb->createNamedParameter(time() - 1, IQueryBuilder::PARAM_INT))->executeStatement();
		$this->linkHistory($token['id']);

		$this->assertSame(1, $this->abandonedLogins()->purge(time()));
		$this->assertFalse($this->tokenExists($token['id']), 'Its session is ended');
		$this->assertSame($this->expected(rows: ['kept'], history: ['failed', 'none'], detections: ['step_up_failed:timeout'], loggedIn: false), $this->snapshot($this->alice));
		$this->assertTrue($this->detectionsOf('step_up_failed')[0]->getExplanationData()['facts']['abandoned'] ?? false);
	}

	private function linkHistory(int $tokenId): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(LoginHistoryMapper::TABLE)->set('session_token_id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT))->executeStatement();
	}

	private function abandonedLogins(): AbandonedLogins {
		return new AbandonedLogins(
			Server::get(StepUpSessionMapper::class),
			Server::get(LoginHistory::class),
			$this->engine(),
			$this->appSettings(),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	private function flagSource(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	private function waitForAnAdministrator(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$this->flagSource();
		$this->startSession($this->bob);
		$this->loginThroughTheApp($this->bob);
		$this->assertNotNull($this->stepUp()?->approvalId);
		$this->assertSame($this->expected(stepUp: 'pending', rows: ['waiting'], history: ['pending', 'none']), $this->snapshot($this->bob));
	}

	/**
	 * @param ?array{string, bool} $confirmation
	 * @param list<string> $rows
	 * @param ?array{?string, string} $history
	 * @param list<string> $detections
	 * @return array<string, mixed>
	 */
	private function expected(?string $stepUp = null, ?array $confirmation = null, ?string $proof = null, array $rows = [], ?array $history = null, array $detections = [], bool $loggedIn = true): array {
		return [
			'stepUp' => $stepUp,
			'confirmation' => $confirmation,
			'proof' => $proof,
			'rows' => $rows,
			'history' => $history,
			'detections' => $detections,
			'loggedIn' => $loggedIn,
		];
	}

	/**
	 * @return array<string, mixed>
	 */
	private function snapshot(IUser $user): array {
		$uid = $user->getUID();
		$confirmation = $this->state->get(SessionMarkers::CONFIRMATION);
		$history = Server::get(LoginHistoryMapper::class)->forUser($uid, 0);
		$detections = [];
		foreach (array_reverse(Server::get(DetectionMapper::class)->findList(new DetectionFilter(uid: $uid, limit: 20))) as $detection) {
			$rule = $detection->getExplanationData()['facts']['rule'] ?? null;
			$detections[] = $detection->getCheckId() . (is_string($rule) ? ':' . $rule : '');
		}
		return [
			'stepUp' => $this->state->get(SessionMarkers::STEP_UP)['status'] ?? null,
			'confirmation' => $confirmation === null ? null : [$confirmation['by'] ?? null, ($confirmation[LoginConfirmation::CLIENT_ONLY] ?? false) === true],
			'proof' => $this->state->get(SessionMarkers::PROOF)['by'] ?? null,
			'rows' => $this->unconfirmedRowsOf($uid),
			'history' => $history === [] ? null : [$history[0]->stepUp, $history[0]->confirmedBy],
			'detections' => $detections,
			'loggedIn' => $this->sessionUser !== null,
		];
	}

	/**
	 * @return list<string> the account's remembered sessions: waiting for a deadline, or kept without one
	 */
	private function unconfirmedRowsOf(string $uid): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('deadline')->from(StepUpSessionMapper::TABLE)->where($qb->expr()->eq('uid', $qb->createNamedParameter($uid)));
		$result = $qb->executeQuery();
		$rows = [];
		while (($deadline = $result->fetchOne()) !== false) {
			$rows[] = $deadline === null ? 'kept' : 'waiting';
		}
		$result->closeCursor();
		sort($rows);
		return $rows;
	}
}
