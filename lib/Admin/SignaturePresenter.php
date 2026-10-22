<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\CustomSignatures;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\Signatures;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * The signatures of the injection probe check for its card: the built-in
 * ones with their switch, and the administrator's own with what is wrong
 * with them, if anything.
 *
 * @psalm-import-type IntrusionDetectionSignatures from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCustomSignature from ResponseDefinitions
 */
class SignaturePresenter {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly CustomSignatures $custom,
	) {
	}

	/**
	 * @return IntrusionDetectionSignatures
	 */
	public function catalog(IL10N $l): array {
		$disabled = $this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_DISABLED);
		$signatures = [];
		foreach (Signatures::catalog($l) as $signature) {
			$signatures[] = $signature + [
				'group' => str_starts_with($signature['id'], 'sql_') ? 'sql' : 'payload',
				'enabled' => !in_array($signature['id'], $disabled, true),
			];
		}
		return [
			'version' => Signatures::VERSION,
			'minWeight' => $this->settings->paramInt(InjectionProbe::ID, InjectionProbe::PARAM_MIN_WEIGHT),
			'signatures' => $signatures,
			'custom' => $this->check($this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM), false, $l),
			'maxCustom' => CustomSignatures::MAX_ITEMS,
			'maxLength' => CustomSignatures::MAX_LENGTH,
			'defaultWeight' => CustomSignatures::DEFAULT_WEIGHT,
		];
	}

	/**
	 * Each entry with its weight and what is wrong with it.
	 *
	 * @param list<string> $entries
	 * @param bool $thorough also run the timing test, as saving does
	 * @return list<IntrusionDetectionCustomSignature>
	 */
	public function check(array $entries, bool $thorough, IL10N $l): array {
		$checked = [];
		foreach ($entries as $entry) {
			$problem = $this->custom->problem($entry, $thorough);
			$weighted = preg_match('~^([1-9]):(.+)$~sD', $entry, $m) === 1;
			$checked[] = [
				'entry' => $entry,
				'id' => CustomSignatures::idFor($entry),
				'weight' => $weighted ? (int)$m[1] : CustomSignatures::DEFAULT_WEIGHT,
				'pattern' => $weighted ? $m[2] : $entry,
				'problem' => $problem,
				'problemText' => $problem === null ? null : self::problemText($problem, $l),
			];
		}
		return $checked;
	}

	public static function problemText(string $problem, IL10N $l): string {
		return match ($problem) {
			CustomSignatures::PROBLEM_TOO_LONG => $l->t('It is longer than %s characters.', [(string)CustomSignatures::MAX_LENGTH]),
			CustomSignatures::PROBLEM_MATCHES_EVERYTHING => $l->t('It matches every value, even an empty one.'),
			CustomSignatures::PROBLEM_TOO_SLOW => $l->t('It is too slow on long input and could be used to overload the server.'),
			default => $l->t('It is not a valid regular expression.'),
		};
	}
}
