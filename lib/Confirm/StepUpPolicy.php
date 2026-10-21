<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCP\IL10N;

/**
 * Why a password login needs extra confirmation (concept section 11.5).
 * Each reason has a policy, which decides what happens when the account
 * has no way to confirm: see {@see self::defaultOutcome()}.
 *
 * The reasons that apply are found by the providers in
 * {@see StepUpReasons::PROVIDERS}; a policy without a provider is not used.
 */
enum StepUpPolicy: string {
	/** The address or its network was part of an attack */
	case FlaggedSource = 'flagged_source';
	/** The password is being tried against many accounts right now */
	case SprayedPassword = 'sprayed_password';
	/** Someone is guessing the account's password */
	case ProtectedAccount = 'protected_account';
	/** The password is on a public list of leaked passwords */
	case BreachedPassword = 'breached_password';
	/** The address belongs to a hosting provider or the Tor network */
	case RiskyNetwork = 'risky_network';
	/** The address has a high risk score */
	case RiskHigh = 'risk_high';
	/** An administrator started lockdown mode */
	case Lockdown = 'lockdown';
	/**
	 * A sensitive action in a risky session (concept section 11.13). Not a
	 * reason at login: the confirm page asks for it, and
	 * `sensitive_no_method` decides when nothing can confirm it.
	 */
	case SensitiveAction = 'sensitive_action';

	/**
	 * What happens by default when no confirmation method is available.
	 */
	public function defaultOutcome(): NoMethodOutcome {
		return match ($this) {
			self::BreachedPassword => NoMethodOutcome::AllowForceChange,
			self::RiskyNetwork => NoMethodOutcome::AllowNotify,
			default => NoMethodOutcome::Refuse,
		};
	}

	/**
	 * The global setting that holds the outcome without a method.
	 */
	public function settingKey(): string {
		return 'step_up_no_method_' . $this->value;
	}

	/**
	 * The reason in the words of the admin page.
	 */
	public function label(IL10N $l): string {
		return match ($this) {
			self::FlaggedSource => $l->t('Login from an address that took part in an attack'),
			self::SprayedPassword => $l->t('Login with a password that attackers are trying right now'),
			self::ProtectedAccount => $l->t('Login to an account whose password is being guessed'),
			self::BreachedPassword => $l->t('Login with a password from a data breach'),
			self::RiskyNetwork => $l->t('Login from a hosting or Tor network'),
			self::RiskHigh => $l->t('Login from an address with a high risk score'),
			self::Lockdown => $l->t('Login during lockdown'),
			self::SensitiveAction => $l->t('A sensitive action in a risky session'),
		};
	}

	/**
	 * The reason as part of a sentence ("… because the address took part in
	 * an attack"), for administrators and the affected user alike.
	 */
	public function because(IL10N $l): string {
		return match ($this) {
			self::FlaggedSource => $l->t('the address or its network took part in an attack'),
			self::SprayedPassword => $l->t('attackers are trying the password against many accounts right now'),
			self::ProtectedAccount => $l->t('someone is guessing the account\'s password'),
			self::BreachedPassword => $l->t('the password is on a public list of leaked passwords'),
			self::RiskyNetwork => $l->t('the address belongs to a hosting provider or the Tor network'),
			self::RiskHigh => $l->t('the address has a high risk score'),
			self::Lockdown => $l->t('lockdown mode was on'),
			self::SensitiveAction => $l->t('a sensitive action needed a fresh confirmation'),
		};
	}

	/**
	 * Stored policy names as one phrase: "a; b". Unknown names are left out.
	 *
	 * @param list<string> $policies
	 */
	public static function describeAll(array $policies, IL10N $l): string {
		$phrases = [];
		foreach ($policies as $policy) {
			$known = self::tryFrom($policy);
			if ($known !== null) {
				$phrases[] = $known->because($l);
			}
		}
		return implode('; ', $phrases);
	}

	/**
	 * Why the default is what it is.
	 */
	public function defaultWhy(IL10N $l): string {
		return match ($this) {
			self::FlaggedSource => $l->t('The address was part of an attack.'),
			self::SprayedPassword => $l->t('Attackers are trying this password right now.'),
			self::ProtectedAccount => $l->t('Someone is guessing this account\'s password.'),
			self::BreachedPassword => $l->t('The password must change anyway, and refusing would lock people out without an attack.'),
			self::RiskyNetwork => $l->t('Hosting networks are suspicious, not evidence.'),
			self::RiskHigh => $l->t('Many signs of an attack come together at this address.'),
			self::Lockdown => $l->t('An administrator chose to lock down.'),
			self::SensitiveAction => $l->t('The session is risky, and the action could hand the account to someone else.'),
		};
	}
}
