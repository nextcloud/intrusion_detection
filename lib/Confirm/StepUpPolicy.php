<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Config\GlobalSettings;
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
	/** An administrator logs in from outside the trusted networks */
	case AdminOutsideNetworks = 'admin_outside_networks';

	/**
	 * What happens by default when no confirmation method is available.
	 */
	public function defaultOutcome(): NoMethodOutcome {
		return NoMethodOutcome::from(GlobalSettings::STEP_UP_NO_METHOD_DEFAULTS[$this->value]);
	}

	/**
	 * Whether an app that sends the password may still log in from a
	 * familiar place ({@see FamiliarLogin}) while the account could confirm
	 * in a browser, with the outcome configured for no method. These
	 * reasons can be caused by others (guessing, a breach list, the
	 * network), so refusing everywhere would let anyone lock out the
	 * account holder's calendar and file apps. The other reasons point at
	 * the login itself and refuse such apps everywhere.
	 */
	public function allowsFamiliarApps(): bool {
		return match ($this) {
			self::ProtectedAccount, self::RiskyNetwork, self::BreachedPassword => true,
			default => false,
		};
	}

	/**
	 * The outcome without a method that lets the login in: with a notice,
	 * and for a leaked password also with a forced password change.
	 */
	public function allowingOutcome(): NoMethodOutcome {
		return $this === self::BreachedPassword ? NoMethodOutcome::AllowForceChange : NoMethodOutcome::AllowNotify;
	}

	/**
	 * Whether a remembered device may confirm a login with this reason at
	 * all. A device proves who holds it, not that the password is still
	 * safe nor where the login comes from: never for a password that is
	 * being sprayed or is known from a breach, nor for an administrator's
	 * login from outside the trusted networks. The others accept it as
	 * `step_up_known_device_ok_for` says.
	 */
	public function knownDeviceMayConfirm(): bool {
		return match ($this) {
			self::SprayedPassword, self::BreachedPassword, self::AdminOutsideNetworks => false,
			default => true,
		};
	}

	/**
	 * Whether a familiar place ({@see FamiliarLogin}) turns a refusal
	 * without a method into a login allowed with a notice. Guessing the
	 * password must not lock the account holder out where they log in.
	 */
	public function familiarPlaceSoftensRefusal(): bool {
		return $this === self::ProtectedAccount;
	}

	/**
	 * The global setting that holds the outcome without a method.
	 */
	public function settingKey(): string {
		return GlobalSettings::stepUpNoMethod($this->value);
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
			self::AdminOutsideNetworks => $l->t('Administrator login from outside the trusted networks'),
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
			self::AdminOutsideNetworks => $l->t('administrators may log in only from the trusted networks, and this address is outside them'),
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
			self::ProtectedAccount => $l->t('Guessing is no proof that anyone has the password, and refusing would let anyone lock out accounts that have no email address or second factor.'),
			self::BreachedPassword => $l->t('The password must change anyway, and refusing would lock people out without an attack.'),
			self::RiskyNetwork => $l->t('Hosting networks are suspicious, not evidence.'),
			self::RiskHigh => $l->t('Many signs of an attack come together at this address.'),
			self::AdminOutsideNetworks => $l->t('You chose that administrators log in from the trusted networks only.'),
		};
	}
}
