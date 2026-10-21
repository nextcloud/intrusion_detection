<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\OpenMetrics\ExporterManager;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\OpenMetrics\ApprovalsPendingMetric;
use OCA\IntrusionDetection\OpenMetrics\BansActiveMetric;
use OCA\IntrusionDetection\OpenMetrics\BlocklistRangesMetric;
use OCA\IntrusionDetection\OpenMetrics\DetectionsMetric;
use OCA\IntrusionDetection\OpenMetrics\GuardSecondsMetric;
use OCA\IntrusionDetection\OpenMetrics\LearningModeMetric;
use OCA\IntrusionDetection\OpenMetrics\LockdownActiveMetric;
use OCA\IntrusionDetection\Response\BanService;
use OCP\App\IAppManager;
use OCP\IConfig;
use OCP\OpenMetrics\IMetricFamily;
use OCP\OpenMetrics\Metric;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The OpenMetrics exporters of concept section 17.4: registered in
 * info.xml, named in core's style, with values from the database, without
 * an address or an account name in any label, and skippable with core's
 * `openmetrics_skipped_classes`.
 */
#[Group('DB')]
class OpenMetricsTest extends IntegrationTestCase {
	private const EXPORTERS = [
		DetectionsMetric::class,
		BansActiveMetric::class,
		GuardSecondsMetric::class,
		LearningModeMetric::class,
		BlocklistRangesMetric::class,
		ApprovalsPendingMetric::class,
		LockdownActiveMetric::class,
	];

	private function detection(string $check, string $severity, bool $enforced, int $createdAt, ?string $ip = null, ?string $uid = null): void {
		$detection = new Detection();
		$detection->setCheckId($check);
		$detection->setSeverity($severity);
		$detection->setEnforced($enforced);
		$detection->setIp($ip);
		$detection->setUid($uid);
		$detection->setExplanationData([]);
		$detection->setActionList([]);
		$detection->setCreatedAt($createdAt);
		$detection->setLastSeenAt($createdAt);
		$detection->setHits(1);
		Server::get(DetectionMapper::class)->insert($detection);
	}

	/**
	 * @return array<string, int|float|bool> values by their labels
	 */
	private static function values(IMetricFamily $family): array {
		$values = [];
		foreach ($family->metrics() as $metric) {
			$labels = $metric->labels;
			ksort($labels);
			$key = json_encode($labels, JSON_THROW_ON_ERROR);
			$values[$key] = $metric->value instanceof \UnitEnum ? $metric->value->value : $metric->value;
		}
		return $values;
	}

	private function cleanCache(): void {
		Server::get(\OCP\ICacheFactory::class)->createLocal(Application::APP_ID . '-metrics')->clear();
	}

	public function testTheExportersAreRegisteredInInfoXml(): void {
		$info = Server::get(IAppManager::class)->getAppInfo(Application::APP_ID);
		$this->assertSame(self::EXPORTERS, array_values((array)($info['openmetrics']['exporter'] ?? [])));
	}

	public function testEveryExporterIsValidAndNamesNoAddressOrAccount(): void {
		$this->detection('credential_stuffing', 'medium', true, time(), '198.51.100.7', 'alice');
		Server::get(BanService::class)->banManually('198.51.100.7', 1, 'admin', 'test');
		$this->cleanCache();

		foreach (self::EXPORTERS as $class) {
			$family = Server::get($class);
			$this->assertInstanceOf(IMetricFamily::class, $family);
			$name = $family->name();
			$this->assertMatchesRegularExpression('/^intrusion_[a-z0-9_]+$/', $name, 'prefixed like the app, lower case');
			if ($family->unit() !== '') {
				$this->assertMatchesRegularExpression('/(^|_)' . $family->unit() . '$/', $name, 'the unit is the suffix of the name');
			}
			$this->assertNotSame('', $family->help());
			$metrics = iterator_to_array($family->metrics(), false);
			$this->assertNotSame([], $metrics, $class . ' always has a value');
			foreach ($metrics as $metric) {
				$this->assertInstanceOf(Metric::class, $metric);
				foreach ($metric->labels as $label => $value) {
					$this->assertMatchesRegularExpression('/^[a-z_][a-z0-9_]*$/', (string)$label);
					$this->assertFalse(filter_var(explode('/', (string)$value)[0], FILTER_VALIDATE_IP), $class . ' has an address in a label');
					$this->assertNotSame('alice', $value, $class . ' has an account in a label');
					$this->assertNotSame('admin', $value, $class . ' has an account in a label');
				}
			}
		}
	}

	public function testTheDetectionsTotalCountsEveryDetectionAndKeepsCountingAfterRetention(): void {
		$old = time() - 200 * 86400;
		$this->detection('credential_stuffing', 'medium', true, $old);
		$this->detection('credential_stuffing', 'medium', true, time());
		$this->detection('trap_url', 'low', false, $old);
		$this->detection('trap_url', 'low', false, time());
		$this->detection('admin_change', 'high', true, time());
		$this->cleanCache();
		$expected = [
			'{"check":"admin_change","enforced":"true","severity":"high"}' => 1,
			'{"check":"credential_stuffing","enforced":"true","severity":"medium"}' => 2,
			'{"check":"trap_url","enforced":"false","severity":"low"}' => 2,
		];
		$this->assertSame($expected, self::values(Server::get(DetectionsMetric::class)));

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertCount(3, Server::get(DetectionMapper::class)->findList(new \OCA\IntrusionDetection\Db\DetectionFilter()), 'the old detections are gone');
		$this->cleanCache();
		$this->assertSame($expected, self::values(Server::get(DetectionsMetric::class)), 'but still counted');
		$this->assertSame(
			['credential_stuffing|medium|1' => 1, 'trap_url|low|0' => 1],
			json_decode($this->appConfig->getValueString(Application::APP_ID, GlobalSettings::DETECTIONS_RETIRED), true),
		);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertSame(['credential_stuffing|medium|1' => 1, 'trap_url|low|0' => 1], json_decode($this->appConfig->getValueString(Application::APP_ID, GlobalSettings::DETECTIONS_RETIRED), true), 'a second run adds nothing');
		$this->assertCount(3, Server::get(DetectionTotals::class)->totals());
	}

	public function testWithoutDetectionsTheTotalIsZero(): void {
		$this->cleanCache();
		$this->assertSame(['[]' => 0], self::values(Server::get(DetectionsMetric::class)));
	}

	public function testActiveBansByScopeAndLevel(): void {
		$bans = Server::get(BanService::class);
		$bans->banManually('198.51.100.7', 1, 'admin', null);
		$bans->banManually('198.51.100.8', 1, 'admin', null);
		$bans->banManually('203.0.113.0/24', 2, 'admin', null);
		$lifted = $bans->banManually('192.0.2.1', 3, 'admin', null);
		$bans->lift($lifted, 'admin', 'a mistake');

		$this->assertSame([
			'{"level":"1","scope":"ip"}' => 2,
			'{"level":"2","scope":"net"}' => 1,
		], self::values(Server::get(BansActiveMetric::class)));
	}

	public function testPendingApprovalsByKind(): void {
		$this->assertSame(['{"kind":"admin_grant"}' => 0], self::values(Server::get(ApprovalsPendingMetric::class)));
		foreach ([Approval::STATUS_PENDING, Approval::STATUS_PENDING, Approval::STATUS_APPROVED] as $i => $status) {
			$approval = new Approval();
			$approval->setKind(Approval::KIND_ADMIN_GRANT);
			$approval->setSubjectUid('ids-metric-' . $i);
			$approval->setRequestedBy('admin');
			$approval->setStatus($status);
			$approval->setCreatedAt(time());
			$approval->setExpiresAt(time() + 3600);
			Server::get(ApprovalMapper::class)->insert($approval);
		}
		$this->assertSame(['{"kind":"admin_grant"}' => 2], self::values(Server::get(ApprovalsPendingMetric::class)));
	}

	public function testEachExporterCanBeSkippedWithCoreSetting(): void {
		foreach (self::EXPORTERS as $skipped) {
			$config = $this->createMock(IConfig::class);
			$config->method('getSystemValue')->willReturnCallback(static fn (string $key, mixed $default): mixed => $key === 'openmetrics_skipped_classes' ? [$skipped] : $default);
			$manager = new ExporterManager(Server::get(IAppManager::class), Server::get(LoggerInterface::class), $config);
			$classes = array_map(static fn (IMetricFamily $family): string => $family::class, iterator_to_array($manager->export(), false));
			$this->assertNotContains($skipped, $classes);
			foreach (array_diff(self::EXPORTERS, [$skipped]) as $kept) {
				$this->assertContains($kept, $classes);
			}
		}
	}
}
