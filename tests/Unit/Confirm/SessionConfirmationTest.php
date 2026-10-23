<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OC\Authentication\TwoFactorAuth\Manager;
use OC\Authentication\TwoFactorAuth\ProviderSet;
use OC\Session\Memory;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\Confirm\LoginConfirmationStore;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCP\Authentication\Token\IProvider as TokenProvider;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\IUser;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SessionConfirmationTest extends TestCase {
	private Memory $session;
	private SessionMarkers $state;

	protected function setUp(): void {
		parent::setUp();
		$this->session = new Memory();
		$this->state = new SessionMarkers($this->session, $this->createMock(LoggerInterface::class));
	}

	public function testALoginThatNeededNothingProvedThePassword(): void {
		$this->assertSame(SessionConfirmation::PASSWORD, $this->confirmation()->level('alice'));
	}

	public function testAPendingRefusedOrUnconfirmedLoginIsUnconfirmed(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Pending, ['flagged_source'], 1, 2))->toArray());
		$this->assertTrue($this->confirmation()->isUnconfirmed('alice'));
		$this->assertSame(SessionConfirmation::PASSWORD, $this->confirmation()->level('bob'), 'Another account\'s marker says nothing');

		$this->state->remove(SessionMarkers::STEP_UP);
		$this->state->set(SessionMarkers::CONFIRMATION, ['uid' => 'alice', 'by' => 'none', 'policies' => [], 'at' => 1]);
		$this->prove('alice', 'second_factor');
		$this->assertTrue($this->confirmation()->isUnconfirmed('alice'), 'Let in without a confirmation, whatever came later');
	}

	public function testAnAppPasswordIsNeverMoreThanUnconfirmed(): void {
		$this->session->set('app_password', 'xxx');
		$this->prove('alice', 'second_factor');
		$this->assertTrue($this->confirmation()->isUnconfirmed('alice'));
	}

	public function testAnAppPasswordCountsAsThePasswordForANo(): void {
		$this->session->set('app_password', 'xxx');
		$this->assertSame(SessionConfirmation::PASSWORD, $this->confirmation()->denialLevel('alice'));
		$this->prove('alice', 'second_factor');
		$this->assertSame(SessionConfirmation::PASSWORD, $this->confirmation()->denialLevel('alice'), 'Never more than the password');
		$this->assertSame(SessionConfirmation::UNCONFIRMED, $this->confirmation()->level('alice'), 'Everything else still asks for more');

		$this->state->set(SessionMarkers::CONFIRMATION, ['uid' => 'alice', 'by' => 'none', 'policies' => [], 'at' => 1]);
		$this->assertSame(SessionConfirmation::UNCONFIRMED, $this->confirmation()->denialLevel('alice'), 'Let in without a confirmation');
		$this->state->remove(SessionMarkers::CONFIRMATION);
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Pending, ['flagged_source'], 1, 2))->toArray());
		$this->assertSame(SessionConfirmation::UNCONFIRMED, $this->confirmation()->denialLevel('alice'), 'Waiting for its confirmation');
	}

	public function testABrowserSessionAnswersNoWithTheLevelOfItsLogin(): void {
		$this->assertSame(SessionConfirmation::PASSWORD, $this->confirmation()->denialLevel('alice'));
		$this->prove('alice', 'second_factor');
		$this->assertSame(SessionConfirmation::PROVEN, $this->confirmation()->denialLevel('alice'));
	}

	public function testAConfirmationOrAProofOfTheLogin(): void {
		foreach (LoginConfirmation::PROOFS as $by) {
			$this->state->set(SessionMarkers::CONFIRMATION, ['uid' => 'alice', 'by' => $by, 'policies' => [], 'at' => 1]);
			$this->assertTrue($this->confirmation()->isProven('alice'), $by);
		}
		$this->state->remove(SessionMarkers::CONFIRMATION);
		$this->prove('alice', 'known_device');
		$this->assertTrue($this->confirmation()->isProven('alice'));
		$this->assertFalse($this->confirmation()->isProven('bob'));
	}

	public function testTheSetupOfASecondFactorIsRequiredOnlyAsCoreRequiresIt(): void {
		$user = $this->createMock(IUser::class);
		$manager = $this->createMock(Manager::class);
		$manager->method('needsSecondFactor')->willReturnOnConsecutiveCalls(false, true, true);
		$manager->method('getProviderSet')->willReturnOnConsecutiveCalls(
			new ProviderSet([$this->provider('totp')], false),
			new ProviderSet([], true),
		);
		$setup = new SecondFactorSetup($manager);
		$this->assertFalse($setup->isRequired($user), 'No second factor needed');
		$this->assertFalse($setup->isRequired($user), 'A provider is set up: the challenge, not the setup');
		$this->assertFalse($setup->isRequired($user), 'A provider app is missing');
	}

	public function testTheSetupIsRequiredWhenEnforcedWithoutAProvider(): void {
		$manager = $this->createMock(Manager::class);
		$manager->method('needsSecondFactor')->willReturn(true);
		$manager->method('getProviderSet')->willReturn(new ProviderSet([], false));
		$this->assertTrue((new SecondFactorSetup($manager))->isRequired($this->createMock(IUser::class)));
	}

	private function provider(string $id): IProvider {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn($id);
		return $provider;
	}

	private function confirmation(): SessionConfirmation {
		return new SessionConfirmation($this->store(), $this->coreSession());
	}

	private function prove(string $uid, string $by): void {
		$this->store()->put(LoginConfirmation::proven($uid, $by, 0));
	}

	private function store(): LoginConfirmationStore {
		return new LoginConfirmationStore($this->state, $this->createMock(UnconfirmedSessions::class), $this->coreSession());
	}

	private function coreSession(): CoreSession {
		return new CoreSession($this->session, $this->createMock(TokenProvider::class), $this->createMock(LoggerInterface::class));
	}
}
