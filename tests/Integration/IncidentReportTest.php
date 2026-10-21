<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChangeDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Command\Report;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReport;
use OCA\IntrusionDetection\Incident\IncidentReportBuilder;
use OCA\IntrusionDetection\Incident\IncidentReports;
use OCA\IntrusionDetection\Incident\ReportFormat;
use OCA\IntrusionDetection\Incident\ReportRenderer;
use OCA\IntrusionDetection\Incident\Sources\ShareSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Constants;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Files\AppData\IAppDataFactory;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Server;
use OCP\Share\IManager;
use OCP\Share\IShare;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * The incident report against the real database: every source, an account
 * and an address as the subject, the period, escaping, and that building a
 * report stores nothing.
 */
#[Group('DB')]
class IncidentReportTest extends LoginFailureTestCase {
	private const SHARE_TOKEN = 'SecretLinkTokenQ7x9';
	private const HTML_NAME = '<img src=x onerror=alert(1)>.txt';
	private const HTML_AGENT = '<script>alert("agent")</script> EvilBrowser/1.0';

	private string $victim;
	private string $other;
	private IManager&MockObject $shareManager;
	/** @var list<CriticalActionPerformedEvent> */
	private array $audited = [];

	protected function setUp(): void {
		parent::setUp();
		$this->victim = 'ids-inc-victim-' . bin2hex(random_bytes(3));
		$this->other = 'ids-inc-other-' . bin2hex(random_bytes(3));
		$this->user($this->victim);
		$this->user($this->other);
		$this->shareManager = $this->createMock(IManager::class);
		Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, function (CriticalActionPerformedEvent $event): void {
			$this->audited[] = $event;
		});
	}

	private function builder(): IncidentReportBuilder {
		$shares = new ShareSource($this->shareManager, Server::get(DateFormatter::class), Server::get(LoggerInterface::class));
		return new IncidentReportBuilder(
			new OverridingContainer([ShareSource::class => $shares]),
			Server::get(IUserManager::class),
			Server::get(IURLGenerator::class),
			Server::get(ITimeFactory::class),
			Server::get(DateFormatter::class),
			Server::get(LoggerInterface::class),
		);
	}

	private function reports(): IncidentReports {
		return new IncidentReports($this->builder(), Server::get(ReportRenderer::class), Server::get(AuditLogger::class));
	}

	private function report(IncidentQuery $query): IncidentReport {
		return $this->builder()->build($query, 'admin', Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
	}

	private function forUser(string $uid, ?int $since = null): IncidentQuery {
		return IncidentQuery::forUser($uid, $since, null, time() + 1);
	}

	private function forAddress(string $ip, ?int $since = null): IncidentQuery {
		return IncidentQuery::forAddress($ip, $since, null, time() + 1);
	}

	/**
	 * @return array<string, int>
	 */
	private static function kindCounts(IncidentReport $report): array {
		return array_column($report->kinds, 'count', 'id');
	}

	private function stuff(string $ip, string $prefix): void {
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin($ip, $prefix . $i, 'Wrong-' . $prefix . '-' . $i);
		}
	}

	/**
	 * The victim's shares, as the share manager returns them: a file with a
	 * name full of markup, shared as a password protected public link and
	 * with the other account. Mocked, so the test needs no file system.
	 */
	private function shareFiles(): void {
		$link = $this->share(IShare::TYPE_LINK, null, Constants::PERMISSION_READ, '$2y$10$SecretShareHashOfThePassword');
		$direct = $this->share(IShare::TYPE_USER, $this->other, Constants::PERMISSION_READ | Constants::PERMISSION_UPDATE, null);
		$this->shareManager->method('getSharesBy')->willReturnCallback(fn (string $uid, int $type, $path, bool $reshares, int $limit, int $offset, bool $onlyValid): array => match (true) {
			$uid !== $this->victim || $offset > 0 || $reshares || $onlyValid => [],
			$type === IShare::TYPE_LINK => [$link],
			$type === IShare::TYPE_USER => [$direct],
			default => [],
		});
	}

	private function share(int $type, ?string $with, int $permissions, ?string $password): IShare {
		$share = $this->createMock(IShare::class);
		$share->method('getShareType')->willReturn($type);
		$share->method('getFullId')->willReturn('ocinternal:' . (700 + $type));
		$share->method('getTarget')->willReturn('/' . self::HTML_NAME);
		$share->method('getSharedWith')->willReturn($with);
		$share->method('getShareTime')->willReturn(new \DateTime('@' . (time() - 300)));
		$share->method('getNodeType')->willReturn('file');
		$share->method('getPermissions')->willReturn($permissions);
		$share->method('getPassword')->willReturn($password);
		$share->method('getExpirationDate')->willReturn(null);
		$share->method('getToken')->willReturn(self::SHARE_TOKEN);
		return $share;
	}

	public function testAnAddressReportHasItsDetectionsBlocksAndAppPasswords(): void {
		Server::get(TokenOriginMapper::class)->record(9001, $this->victim, '198.51.100.7', 77, time() - 30);
		$this->stuff('198.51.100.7', 'stuffed');
		$this->stuff('203.0.113.50', 'elsewhere');
		[$ban] = Server::get(BanMapper::class)->findActiveForKeys(['198.51.100.7'], time());
		Server::get(BanService::class)->lift($ban, 'admin', 'Our own scanner');

		$report = $this->report($this->forAddress('198.51.100.7'));
		$kinds = self::kindCounts($report);
		$this->assertSame(1, $kinds['detection']);
		$this->assertSame(1, $kinds['block']);
		$this->assertSame(1, $kinds['block_lifted']);
		$this->assertSame(1, $kinds['app_password']);
		$this->assertSame(0, $kinds['share'], 'shares belong to accounts, not addresses');

		$ids = array_map(static fn (TimelineEntry $e): string => $e->kind, $report->entries);
		$this->assertSame(['app_password', 'detection', 'block', 'block_lifted'], $ids, 'oldest first, and within one second in the order of the sources');
		foreach ($report->entries as $entry) {
			$this->assertStringNotContainsString('203.0.113.50', json_encode($entry->toArray(), JSON_THROW_ON_ERROR), 'nothing about another address');
		}
		$detection = $report->entries[1];
		$this->assertSame(CredentialStuffing::ID, Server::get(\OCA\IntrusionDetection\Db\DetectionMapper::class)->findById((int)$detection->ref['id'])->getCheckId());
		$this->assertTrue($detection->enforced);
		$this->assertNotSame([], $detection->done);
		$this->assertContains('Client: curl/8.0', $detection->details);
		$this->assertStringContainsString('Our own scanner', implode(' ', $report->entries[3]->details));
		$this->assertSame('App password created for ' . $this->victim, $report->entries[0]->title);
		$this->assertContains('Accounts involved: ' . $this->victim, $report->summary->affected);
		$this->assertSame($report->entries[1]->at, $report->summary->foundAt);
	}

	public function testAnIpv6AddressReportCoversItsNetwork(): void {
		$this->stuff('2001:db8:5:6::1', 'six');
		$report = $this->report($this->forAddress('2001:db8:5:6::99'));
		$this->assertSame(1, self::kindCounts($report)['detection']);
		$this->assertSame(1, self::kindCounts($report)['block']);
		$this->assertSame(0, self::kindCounts($this->report($this->forAddress('2001:db8:5:7::1')))['detection']);
	}

	public function testAnAccountReportMergesEverySource(): void {
		Server::get(TokenOriginMapper::class)->record(9101, $this->victim, '192.0.2.200', null, time() - 120);
		Server::get(TokenOriginMapper::class)->record(9102, $this->other, '192.0.2.201', null, time() - 120);
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('192.0.2.' . ($i % 5 + 1), $this->victim, 'Guess-' . $i);
		}
		$this->shareFiles();
		$this->appConfig->setValueString(Application::APP_ID, 'check_' . AdminChange::ID . '_mode', Mode::Protect->value);
		Server::get(AdminChangeDetector::class)->record(AdminChange::KIND_APP_ENABLED, Severity::Medium, $this->victim, null, ['app' => 'files_external', 'groups' => []], 'test');
		Server::get(AdminChangeDetector::class)->record(AdminChange::KIND_APP_ENABLED, Severity::Medium, $this->other, null, ['app' => 'files_external', 'groups' => []], 'test');
		$approval = new Approval();
		$approval->setKind(Approval::KIND_ADMIN_GRANT);
		$approval->setSubjectUid($this->other);
		$approval->setRequestedBy($this->victim);
		$approval->setGroupId('admin');
		$approval->setStatus(Approval::STATUS_REJECTED);
		$approval->setDecidedBy('admin');
		$approval->setCreatedAt(time() - 600);
		$approval->setDecidedAt(time() - 60);
		$approval->setExpiresAt(time() + 3600);
		Server::get(ApprovalMapper::class)->insert($approval);

		$report = $this->report($this->forUser($this->victim));
		$kinds = self::kindCounts($report);
		$this->assertSame(1, $kinds['detection'], 'the account under attack');
		$this->assertSame(1, $kinds['app_password']);
		$this->assertSame(2, $kinds['share']);
		$this->assertSame(1, $kinds['admin_change'], 'only the change the account made');
		$this->assertSame(1, $kinds['approval']);

		$times = array_map(static fn (TimelineEntry $e): int => $e->at, $report->entries);
		$sorted = $times;
		sort($sorted);
		$this->assertSame($sorted, $times, 'chronological');

		$json = json_encode($report->toArray(), JSON_THROW_ON_ERROR);
		$this->assertStringNotContainsString('9102', $json, "the other account's app password is not part of it");
		$this->assertStringContainsString('192.0.2.200', $json);
		$titles = array_map(static fn (TimelineEntry $e): string => $e->title, $report->entries);
		$this->assertContains('Public link to "' . self::HTML_NAME . '" created', $titles);
		$this->assertContains('"' . self::HTML_NAME . '" shared with ' . $this->other, $titles);
		$this->assertContains('Rejected by admin: ' . $this->other . ' to become an administrator', $titles);
		$share = array_values(array_filter($report->entries, static fn (TimelineEntry $e): bool => $e->kind === 'share' && str_starts_with($e->title, 'Public link')))[0];
		$this->assertContains('It has a password.', $share->details);

		$summary = $report->summary;
		$this->assertStringContainsString('the account ' . $this->victim, $summary->headline);
		$this->assertContains('Shared files and folders, and the people or links that received them', $summary->dataCategories);
		$this->assertContains('Administration rights, server settings and other accounts', $summary->dataCategories);
		$this->assertContains('Everything that can be reached with the app passwords created in this period', $summary->dataCategories);
		$this->assertNotSame([], $summary->openItems);
		$notes = array_column(array_map(static fn ($n): array => $n->toArray(), $report->notes), 'id');
		$this->assertContains('file_actions', $notes);
	}

	public function testAnAccountReportHasTheAttacksThatTargetedIt(): void {
		$this->failLogin('198.51.100.20', $this->victim, 'Wrong-a');
		for ($i = 1; $i <= 9; $i++) {
			$this->failLogin('198.51.100.20', 'nobody' . $i, 'Wrong-b' . $i);
		}
		$approval = new Approval();
		$approval->setKind(Approval::KIND_ADMIN_GRANT);
		$approval->setSubjectUid($this->victim);
		$approval->setRequestedBy($this->other);
		$approval->setGroupId('admin');
		$approval->setStatus(Approval::STATUS_PENDING);
		$approval->setCreatedAt(time() - 10);
		$approval->setExpiresAt(time() + 3600);
		Server::get(ApprovalMapper::class)->insert($approval);

		$report = $this->report($this->forUser($this->victim));
		$titles = array_map(static fn (TimelineEntry $e): string => $e->kind . ': ' . $e->title, $report->entries);
		$this->assertContains('detection: Credential stuffing', $titles, 'the stuffing run tried this account');
		$this->assertContains('approval: Request waiting for approval: ' . $this->victim . ' to become an administrator', $titles);
		$this->assertStringContainsString('still waiting', implode(' ', $report->summary->openItems));

		$this->assertSame(0, self::kindCounts($this->report($this->forUser($this->other)))['detection'], 'the other account was not targeted');
	}

	public function testMeasuresAreOnlyWhatReallyRan(): void {
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$detection = new \OCA\IntrusionDetection\Db\Detection();
		$detection->setCheckId(CredentialStuffing::ID);
		$detection->setSeverity('medium');
		$detection->setEnforced(true);
		$detection->setExplanationData([]);
		$detection->setCreatedAt(time());
		$detection->setLastSeenAt(time());
		$detection->setHits(1);
		$detection->setActionList([
			['type' => 'notify_user', 'enforced' => true, 'note' => 'nothing_to_do'],
			['type' => 'flag_source', 'enforced' => true, 'note' => 'failed'],
			['type' => 'notify_admin', 'enforced' => true, 'ref' => ['admins' => 2, 'emails' => 0]],
		]);
		$measures = Server::get(\OCA\IntrusionDetection\Incident\Measures::class)->of($detection, $l);
		$all = Server::get(\OCA\IntrusionDetection\Explain\NarrativeBuilder::class)->build($detection, $l)->done;
		$this->assertNotSame([], $measures);
		$this->assertLessThan(count($all), count($measures));
		$this->assertStringNotContainsString('Nothing needed to be done', implode(' ', $measures));
		$this->assertStringNotContainsString('this failed', implode(' ', $measures));
		$this->assertCount(3, $detection->getActionList(), 'the detection itself is not changed');

		$detection->setEnforced(false);
		$this->assertSame([], Server::get(\OCA\IntrusionDetection\Incident\Measures::class)->of($detection, $l), 'observed detections did nothing');
	}

	public function testOnlyThePeriodCounts(): void {
		$this->stuff('198.51.100.7', 'old');
		$qb = $this->db->getQueryBuilder();
		$qb->update('ids_detections')
			->set('created_at', $qb->createNamedParameter(time() - 10 * 86400))
			->set('last_seen_at', $qb->createNamedParameter(time() - 10 * 86400 + 60))
			->executeStatement();

		$this->assertSame(0, self::kindCounts($this->report($this->forAddress('198.51.100.7')))['detection'], 'the default period is the last 7 days');
		$this->assertSame(1, self::kindCounts($this->report($this->forAddress('198.51.100.7', time() - 11 * 86400)))['detection']);
		$this->assertSame(0, self::kindCounts($this->report(IncidentQuery::forAddress('198.51.100.7', time() - 30 * 86400, time() - 20 * 86400, time())))['detection']);
	}

	public function testTheDocumentsAreEscapedSelfContainedAndHoldNoShareSecrets(): void {
		$this->shareFiles();
		Server::get(ResponseEngine::class)->handle(new DetectionDraft(
			checkId: CredentialStuffing::ID,
			source: SourceKey::fromIp('198.51.100.9'),
			uid: $this->victim,
			facts: ['failures' => 12, 'names' => 6, 'targets' => [$this->victim]],
			userAgent: self::HTML_AGENT,
		));
		Server::get(BanService::class)->banManually('198.51.100.9', 1, 'admin', '<b onmouseover="alert(2)">really bad</b>');

		$reports = $this->reports();
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach ([$this->forUser($this->victim), $this->forAddress('198.51.100.9')] as $query) {
			$html = $reports->document($query, ReportFormat::Html, 'admin', $l);
			$body = $html['body'];
			$this->assertStringStartsWith('<!DOCTYPE html>', $body);
			$this->assertStringContainsString('<meta http-equiv="Content-Security-Policy" content="default-src &#039;none&#039;', str_replace("'", '&#039;', $body));
			$this->assertSelfContained($body);
			$this->assertStringContainsString('&lt;script&gt;alert(&quot;agent&quot;)&lt;/script&gt;', $body);
			$this->assertSame('text/html; charset=utf-8', $html['contentType']);
			$this->assertMatchesRegularExpression('/^incident-report-[a-z0-9.-]+-\d{8}-\d{6}\.html$/', $html['filename']);

			$json = $reports->document($query, ReportFormat::Json, 'admin', $l)['body'];
			$data = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
			$this->assertSame(IncidentReport::SCHEMA_VERSION, $data['schemaVersion']);
			$this->assertStringNotContainsString('<', $json, 'markup is escaped in the JSON as well');

			foreach ([$body, $json] as $document) {
				$this->assertStringNotContainsString(self::SHARE_TOKEN, $document, 'the share token never appears');
				$this->assertStringNotContainsString('SecretShareHash', $document, 'nor the hash of the share password');
			}
		}
		$this->assertStringContainsString('&lt;img src=x onerror=alert(1)&gt;.txt', $reports->document($this->forUser($this->victim), ReportFormat::Html, 'admin', $l)['body']);
	}

	public function testBuildingAReportStoresNothing(): void {
		$this->stuff('198.51.100.7', 'stuffed');
		$this->shareFiles();
		Server::get(TokenOriginMapper::class)->record(9201, $this->victim, '198.51.100.7', null, time());

		$snapshot = function (): array {
			$rows = [];
			foreach (self::TABLES as $table) {
				$rows[$table] = $this->allRows($table);
			}
			$this->appConfig->clearCache();
			$config = [];
			foreach ($this->appConfig->getKeys(Application::APP_ID) as $key) {
				$config[$key] = $this->appConfig->getValueMixed(Application::APP_ID, $key);
			}
			$appData = Server::get(IAppDataFactory::class)->get(Application::APP_ID);
			try {
				$folders = array_map(static fn ($f): string => $f->getName(), $appData->getDirectoryListing());
			} catch (\Throwable) {
				$folders = [];
			}
			return [$rows, $config, $folders];
		};

		$before = $snapshot();
		$reports = $this->reports();
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach ([$this->forUser($this->victim), $this->forAddress('198.51.100.7')] as $query) {
			$reports->report($query, 'admin', $l);
			$reports->document($query, ReportFormat::Json, 'admin', $l);
			$reports->document($query, ReportFormat::Html, 'admin', $l);
		}
		$this->assertSame($before, $snapshot(), 'no row, setting or file was written');
		$this->assertCount(6, array_filter($this->audited, static fn (CriticalActionPerformedEvent $e): bool => str_contains($e->getLogMessage(), 'incident report')), 'but every report was audited');
	}

	public function testTheCommandWritesTheReportToStandardOutputAndIsAudited(): void {
		$this->stuff('198.51.100.7', 'stuffed');

		[$code, $output] = $this->runCommand(['--ip' => '198.51.100.7']);
		$this->assertSame(Command::SUCCESS, $code);
		$data = json_decode($output, true, 64, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $data['schemaVersion']);
		$this->assertSame('occ', $data['generatedBy']);
		$this->assertSame('198.51.100.7', $data['subject']['value']);
		$this->assertSame('detection', $data['entries'][0]['kind']);

		[$code, $output] = $this->runCommand(['--user' => $this->victim, '--format' => 'html', '--since' => '2026-01-01 00:00', '--until' => (string)time()]);
		$this->assertSame(Command::INVALID, $code, 'longer than 90 days');
		[$code, $output] = $this->runCommand(['--user' => $this->victim, '--format' => 'html', '--since' => (string)(time() - 3600)]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringStartsWith('<!DOCTYPE html>', $output);

		$this->assertSame(Command::INVALID, $this->runCommand([])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(['--user' => 'alice', '--ip' => '198.51.100.7'])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(['--ip' => '198.51.100.7', '--format' => 'pdf'])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(['--ip' => '198.51.100.7', '--since' => 'next blursday'])[0]);

		$audited = array_values(array_filter($this->audited, static fn (CriticalActionPerformedEvent $e): bool => str_contains($e->getLogMessage(), 'incident report')));
		$this->assertCount(2, $audited);
		$this->assertSame(['subjectType' => 'address', 'subject' => '198.51.100.7'], array_slice($audited[0]->getParameters(), 0, 2));
		$this->assertSame('occ', $audited[0]->getParameters()['actor']);
		$this->assertSame('html', $audited[1]->getParameters()['format']);
	}

	/**
	 * The page has only the elements the template writes, no event handler
	 * and nothing that loads a resource: no script, image, frame, form, style
	 * sheet or font, and only the one inline style block.
	 */
	private function assertSelfContained(string $html): void {
		$this->assertStringNotContainsStringIgnoringCase('<script', $html);
		$document = new \DOMDocument();
		// libxml does not know the HTML5 elements; that is all it would complain about.
		$internal = libxml_use_internal_errors(true);
		$loaded = $document->loadHTML($html, LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NONET);
		libxml_clear_errors();
		libxml_use_internal_errors($internal);
		$this->assertTrue($loaded);
		$allowed = ['html', 'head', 'meta', 'title', 'style', 'body', 'header', 'p', 'h1', 'h2', 'h3', 'h4', 'dl', 'dt', 'dd', 'div', 'section', 'ul', 'ol', 'li', 'span', 'a', 'footer'];
		$styles = 0;
		foreach ($document->getElementsByTagName('*') as $element) {
			$this->assertContains($element->tagName, $allowed, '<' . $element->tagName . '> must not be in the page');
			foreach ($element->attributes ?? [] as $attribute) {
				$name = strtolower($attribute->name);
				$this->assertStringStartsNotWith('on', $name, 'no event handlers');
				$this->assertNotContains($name, ['src', 'srcset', 'style', 'action', 'formaction', 'background', 'poster', 'data'], $name . ' must not be in the page');
				if ($name === 'href') {
					$this->assertSame('a', $element->tagName);
				}
			}
			if ($element->tagName === 'style') {
				$styles++;
				$this->assertStringNotContainsStringIgnoringCase('url(', $element->textContent);
				$this->assertStringNotContainsStringIgnoringCase('@import', $element->textContent);
				$this->assertStringNotContainsStringIgnoringCase('@font-face', $element->textContent);
			}
		}
		$this->assertSame(1, $styles);
	}

	/**
	 * @param array<string, string> $options
	 * @return array{0: int, 1: string}
	 */
	private function runCommand(array $options): array {
		$output = new BufferedOutput();
		$code = Server::get(Report::class)->run(new ArrayInput($options), $output);
		return [$code, $output->fetch()];
	}
}
