<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Repair;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Migration\Version1000Date20261022100000;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\IAppConfig;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;
use Psr\Log\LoggerInterface;

/**
 * Deletes the stored values of settings the app no longer has. A value that
 * differed from that setting's default is logged once, with what applies
 * instead, so that nobody loses a tuned value silently.
 *
 * `history_retention_days` is merged into `retention_detections_days` by
 * {@see Version1000Date20261022100000}, which logs the result; here it is
 * only deleted.
 *
 * Runs after every upgrade and does nothing once the values are gone.
 */
class RemoveRetiredSettings implements IRepairStep {
	public const HISTORY_RETENTION_DAYS = 'history_retention_days';

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * The retired settings: their last default, and what applies instead.
	 *
	 * @return array<string, array{0: int|float|bool|list<string>, 1: string}>
	 */
	public static function retired(): array {
		$points = static fn (string $fact): string => RiskScorer::POINTS[$fact] . ' points';
		$seconds = static fn (int $value): string => $value . ' seconds';
		return [
			'risk_points_attack_tool' => [2, $points(RiskAssessment::FACT_ATTACK_TOOL)],
			'risk_points_tor' => [2, $points(RiskAssessment::FACT_TOR)],
			'risk_points_hosting' => [1, $points(RiskAssessment::FACT_HOSTING)],
			'risk_points_blocklist' => [2, $points(RiskAssessment::FACT_BLOCKLIST)],
			'risk_points_trap' => [3, $points(RiskAssessment::FACT_TRAP)],
			'risk_points_flagged' => [2, $points(RiskAssessment::FACT_FLAGGED)],
			'risk_points_failures' => [1, $points(RiskAssessment::FACT_FAILURES)],
			'risk_points_office' => [-10, $points(RiskAssessment::FACT_OFFICE)],
			'risk_tier_elevated' => [2, RiskAssessment::SCORE_ELEVATED . ' points'],
			'risk_tier_high' => [4, RiskAssessment::SCORE_HIGH . ' points'],
			'risk_factor_elevated' => [0.5, (string)RiskAssessment::FACTOR_ELEVATED],
			'risk_factor_high' => [0.25, (string)RiskAssessment::FACTOR_HIGH],
			'risk_attack_tool_patterns' => [[], 'the built-in list of attack tools only'],
			'step_up_code_ttl' => [600, $seconds(EmailCodes::TTL)],
			'step_up_session_ttl' => [900, $seconds(StepUpService::SESSION_TTL)],
			'step_up_admin_approval_ttl' => [1800, $seconds(AdminApprovalMethod::TTL)],
			'admin_change_approval_ttl' => [604800, $seconds(ApprovalService::TTL)],
			'known_device_duration' => [180 * 86400, $seconds(KnownDevices::DURATION)],
			'trusted_network_duration' => [30 * 86400, $seconds(TrustedNetworks::DURATION)],
			'flag_duration' => [86400, $seconds(FlaggedSources::DURATION)],
			'blocklist_sync_interval' => [21600, $seconds(BlocklistSync::INTERVAL)],
			'digest_send_quiet' => [true, 'quiet digests are always sent'],
			'learning_decoys_act' => [true, 'decoys always act during learning'],
			'blocklist_max_entries' => [200000, BlocklistSync::MAX_ENTRIES . ' entries'],
		];
	}

	#[\Override]
	public function getName(): string {
		return 'Remove retired intrusion detection settings';
	}

	#[\Override]
	public function run(IOutput $output): void {
		$retired = self::retired();
		$stored = array_intersect($this->appConfig->getKeys(Application::APP_ID), [...array_keys($retired), self::HISTORY_RETENTION_DAYS]);
		if ($stored === []) {
			return;
		}
		$values = $this->appConfig->getAllValues(Application::APP_ID);

		foreach ($stored as $key) {
			if (isset($retired[$key])) {
				[$default, $applies] = $retired[$key];
				if (!self::same($values[$key] ?? null, $default)) {
					$this->tell($output, sprintf('Intrusion detection: "%s" is no longer a setting. It was %s; now: %s.', $key, self::display($values[$key] ?? null), $applies));
				}
			}
			$this->appConfig->deleteKey(Application::APP_ID, $key);
		}
	}

	private function tell(IOutput $output, string $message): void {
		$this->logger->info($message, ['app' => Application::APP_ID]);
		$output->info($message);
	}

	/**
	 * Whether a stored value, typed or a plain string, equals a default.
	 *
	 * @param int|float|bool|list<string> $default
	 */
	private static function same(mixed $value, int|float|bool|array $default): bool {
		if (is_array($default)) {
			$value = is_string($value) ? json_decode($value, true) : $value;
			return $value === $default;
		}
		if (is_bool($default)) {
			$value = is_string($value) ? in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true) : $value;
			return $value === $default;
		}
		return is_numeric($value) && (float)$value === (float)$default;
	}

	private static function display(mixed $value): string {
		if (is_bool($value)) {
			return $value ? 'on' : 'off';
		}
		if (is_scalar($value)) {
			return (string)$value;
		}
		return (string)json_encode($value);
	}
}
