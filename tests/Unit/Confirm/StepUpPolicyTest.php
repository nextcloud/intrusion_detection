<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpReference;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Response\BanService;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The step-up policies, their settings, the session state and the
 * reference of refused logins.
 */
class StepUpPolicyTest extends TestCase {
	/**
	 * Concept section 11.5, the table of outcomes without a method.
	 *
	 * @return array<string, array{StepUpPolicy, NoMethodOutcome}>
	 */
	public static function defaults(): array {
		return [
			'flagged_source' => [StepUpPolicy::FlaggedSource, NoMethodOutcome::Refuse],
			'sprayed_password' => [StepUpPolicy::SprayedPassword, NoMethodOutcome::Refuse],
			'protected_account' => [StepUpPolicy::ProtectedAccount, NoMethodOutcome::AllowNotify],
			'breached_password' => [StepUpPolicy::BreachedPassword, NoMethodOutcome::AllowForceChange],
			'risky_network' => [StepUpPolicy::RiskyNetwork, NoMethodOutcome::AllowNotify],
			'risk_high' => [StepUpPolicy::RiskHigh, NoMethodOutcome::Refuse],
			'admin_outside_networks' => [StepUpPolicy::AdminOutsideNetworks, NoMethodOutcome::Refuse],
		];
	}

	#[DataProvider('defaults')]
	public function testTheOutcomeWithoutAMethodDefaultsAsTheConceptSays(StepUpPolicy $policy, NoMethodOutcome $outcome): void {
		$this->assertSame($outcome, $policy->defaultOutcome());
		$this->assertSame('step_up_no_method_' . $policy->value, $policy->settingKey());
	}

	public function testEveryPolicyWithAReasonHasItsSettingWithTheDefault(): void {
		$globals = new GlobalSettings();
		$this->assertSame(
			[StepUpPolicy::FlaggedSource, StepUpPolicy::SprayedPassword, StepUpPolicy::ProtectedAccount, StepUpPolicy::BreachedPassword, StepUpPolicy::RiskyNetwork, StepUpPolicy::RiskHigh, StepUpPolicy::AdminOutsideNetworks],
			StepUpReasons::policies(),
		);
		foreach (StepUpReasons::PROVIDERS as $class) {
			$this->assertTrue(is_subclass_of($class, IStepUpReason::class), $class);
		}
		foreach (StepUpPolicy::cases() as $policy) {
			$definition = $globals->get($policy->settingKey());
			if (!in_array($policy, StepUpReasons::policies(), true)) {
				$this->assertNull($definition, 'No setting for a policy without a reason: ' . $policy->value);
				continue;
			}
			$this->assertNotNull($definition, $policy->value);
			$this->assertSame(ParamType::Choice, $definition->type);
			$this->assertSame($policy->defaultOutcome()->value, $definition->default);
			$this->assertSame(['refuse', 'allow_notify', 'allow_force_change'], $definition->choices);
			$this->assertLessThanOrEqual(64, strlen($policy->settingKey()));
		}
		$this->assertSame(array_map(static fn (StepUpPolicy $p): string => $p->value, StepUpReasons::policies()), array_keys(GlobalSettings::STEP_UP_NO_METHOD_DEFAULTS));
		$this->assertSame(array_map(static fn (NoMethodOutcome $o): string => $o->value, NoMethodOutcome::cases()), GlobalSettings::NO_METHOD_OUTCOMES);
		foreach (StepUpPolicy::cases() as $policy) {
			$this->assertSame($policy->knownDeviceMayConfirm(), preg_match(GlobalSettings::STEP_UP_KNOWN_DEVICE_PATTERN, $policy->value) === 1, $policy->value);
		}
	}

	public function testReasonsAreDescribedInPlainWords(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->assertSame(
			'the address or its network took part in an attack; the password is on a public list of leaked passwords',
			StepUpPolicy::describeAll(['flagged_source', 'no_such_policy', 'breached_password'], $l),
		);
		$this->assertSame('', StepUpPolicy::describeAll([], $l));
	}

	public function testTheStateRoundTripsAndRejectsGarbage(): void {
		$state = new StepUpState('alice', ConfirmationStatus::Pending, ['flagged_source'], 100, 1000, '198.51.100.7', ['email_code'], '$2y$hash', 700, 2, [150, 160], null, 42, true);
		$copy = StepUpState::fromArray($state->toArray());
		$this->assertEquals($state, $copy);
		$this->assertNull(StepUpState::fromArray([]));
		$this->assertNull(StepUpState::fromArray(['uid' => 'alice', 'status' => 'confirmed']));
		$this->assertSame([], StepUpState::fromArray(['uid' => 'a', 'status' => 'pending', 'methods' => 'x', 'resends' => ['a', 3]])?->methods);
		$this->assertSame([3], StepUpState::fromArray(['uid' => 'a', 'status' => 'pending', 'resends' => ['a', 3]])?->resends);
	}

	public function testReferencesEncodeTheDetectionLikeBlockReferences(): void {
		foreach ([1, 31, 32, 2735, 123456789] as $id) {
			$reference = StepUpReference::of($id);
			$this->assertMatchesRegularExpression('/^S[' . BanService::REFERENCE_CHARS . ']{3}-[' . BanService::REFERENCE_CHARS . ']{4}$/', $reference);
			$this->assertSame($id, StepUpReference::detectionId($reference));
			$this->assertSame($id, StepUpReference::detectionId(strtolower(str_replace('-', '', $reference))), 'as typed by a person');
		}
		$this->assertNull(StepUpReference::detectionId('K7Q2-MPXA'), 'A block reference is not one');
		$this->assertNull(StepUpReference::detectionId('SAAA-AAA0'), 'Not in the alphabet');
		$this->assertNull(StepUpReference::detectionId('SAAA-AAAA'), 'No detection 0');
		$this->assertNull(StepUpReference::detectionId('S'));
	}

	public function testTheKnownDeviceDefaultOffersOnlyReasonsADeviceMayConfirm(): void {
		foreach (GlobalSettings::STEP_UP_KNOWN_DEVICE_DEFAULT as $policy) {
			$this->assertTrue(StepUpPolicy::from($policy)->knownDeviceMayConfirm(), $policy);
		}
	}
}
