<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * Explains the risk score a detection stored: one sentence for the
 * narrative ("The limit for this address was 5 instead of 10, because its
 * risk score was 3 (cloud hosting network +1, attack tool "curl" +2).", or
 * "… because lockdown mode was on.") and the breakdown the detection detail
 * shows.
 *
 * @psalm-import-type IntrusionDetectionRisk from ResponseDefinitions
 */
class RiskExplainer {
	/**
	 * @return list<string> nothing when the detection has no score, or a score of 0 that changed nothing
	 */
	public function sentences(Detection $detection, IL10N $l, ?CheckTexts $texts): array {
		[$risk, $lowered, $lockdown] = self::stored($detection);
		if ($risk === null && !$lockdown) {
			return [];
		}
		$scored = $risk !== null && $risk->factor < 1.0;
		if ($lowered !== []) {
			$because = match (true) {
				$lockdown && $scored && $risk !== null => $l->t('lockdown mode was on and the address\'s risk score was %1$s (%2$s)', [(string)$risk->score, $this->breakdown($risk, $l)]),
				$lockdown => $l->t('lockdown mode was on'),
				$risk !== null => $l->t('its risk score was %1$s (%2$s)', [(string)$risk->score, $this->breakdown($risk, $l)]),
				default => '',
			};
			if (count($lowered) === 1) {
				$limit = reset($lowered);
				return [$l->t('The limit for this address was %1$s instead of %2$s, because %3$s.', [(string)$limit['effective'], (string)$limit['plain'], $because])];
			}
			$limits = [];
			foreach ($lowered as $name => $limit) {
				$limits[] = $l->t('%1$s: %2$s instead of %3$s', [$texts?->param($name)->label ?? $name, (string)$limit['effective'], (string)$limit['plain']]);
			}
			return [$l->t('The limits for this address were lower, because %1$s: %2$s.', [$because, implode('; ', $limits)])];
		}
		if ($risk === null || $risk->parts === []) {
			return [];
		}
		return [$l->t('The risk score of the address was %1$s (%2$s).', [(string)$risk->score, $this->breakdown($risk, $l)])];
	}

	/**
	 * The breakdown for the detection detail, or null when it has no score.
	 *
	 * @return ?IntrusionDetectionRisk
	 */
	public function present(Detection $detection, IL10N $l, ?CheckTexts $texts): ?array {
		[$risk, $lowered] = self::stored($detection);
		if ($risk === null) {
			return null;
		}
		$parts = [];
		foreach ($risk->parts as $part) {
			$parts[] = ['fact' => $part['fact'], 'label' => $this->label($part, $l), 'points' => $part['points']];
		}
		$limits = [];
		foreach ($lowered as $name => $limit) {
			$limits[] = ['param' => $name, 'label' => $texts?->param($name)->label ?? $name, 'plain' => $limit['plain'], 'effective' => $limit['effective']];
		}
		return [
			'score' => $risk->score,
			'tier' => $risk->tier,
			'tierLabel' => $this->tierLabel($risk->tier, $l),
			'tierElevated' => $risk->tierElevated,
			'tierHigh' => $risk->tierHigh,
			'parts' => $parts,
			'lowered' => $limits,
		];
	}

	/**
	 * "cloud hosting network +1, attack tool "curl" +2", or "nothing
	 * suspicious" for a score without parts.
	 */
	public function breakdown(RiskAssessment $risk, IL10N $l): string {
		if ($risk->parts === []) {
			return $l->t('nothing suspicious');
		}
		return implode(', ', array_map(
			fn (array $part): string => $this->label($part, $l) . ' ' . ($part['points'] > 0 ? '+' : '') . $part['points'],
			$risk->parts,
		));
	}

	/**
	 * @param array{fact: string, points: int, detail: ?string} $part
	 */
	public function label(array $part, IL10N $l): string {
		$detail = (string)$part['detail'];
		return match ($part['fact']) {
			RiskAssessment::FACT_ATTACK_TOOL => $l->t('attack tool "%s"', [$detail]),
			RiskAssessment::FACT_TOR => $l->t('Tor exit node'),
			RiskAssessment::FACT_HOSTING => $l->t('cloud hosting network'),
			RiskAssessment::FACT_BLOCKLIST => $l->t('on a blocklist that only observes'),
			RiskAssessment::FACT_TRAP => $l->t('trap or reserved name in the last 24 hours'),
			RiskAssessment::FACT_FLAGGED => $l->t('marked after an attack'),
			RiskAssessment::FACT_FAILURES => $l->n('%n failed login in the last hour', '%n failed logins in the last hour', (int)$detail),
			RiskAssessment::FACT_OFFICE => $l->t('office network %s', [$detail]),
			default => $part['fact'],
		};
	}

	public function tierLabel(string $tier, IL10N $l): string {
		return match ($tier) {
			RiskAssessment::TIER_HIGH => $l->t('High'),
			RiskAssessment::TIER_ELEVATED => $l->t('Elevated'),
			default => $l->t('Normal'),
		};
	}

	/**
	 * @return array{0: ?RiskAssessment, 1: array<string, array{plain: int, effective: int}>, 2: bool} the score, the lowered limits, and whether lockdown lowered them
	 */
	private static function stored(Detection $detection): array {
		$facts = $detection->getExplanationData()['facts'] ?? null;
		if (!is_array($facts)) {
			return [null, [], false];
		}
		$risk = RiskAssessment::fromArray($facts[RiskAssessment::FACTS_KEY] ?? null);
		$lockdown = is_array($facts[RiskLimits::LOCKDOWN_KEY] ?? null);
		$lowered = [];
		$stored = $facts[RiskLimits::FACTS_KEY] ?? null;
		if (($risk !== null || $lockdown) && is_array($stored)) {
			foreach ($stored as $name => $limit) {
				if (is_string($name) && is_array($limit) && is_int($limit['plain'] ?? null) && is_int($limit['effective'] ?? null)) {
					$lowered[$name] = ['plain' => $limit['plain'], 'effective' => $limit['effective']];
				}
			}
		}
		return [$risk, $lowered, $lockdown];
	}
}
