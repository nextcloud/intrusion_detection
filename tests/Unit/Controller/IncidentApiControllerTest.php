<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Controller\IncidentApiController;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReport;
use OCA\IntrusionDetection\Incident\IncidentReportBuilder;
use OCA\IntrusionDetection\Incident\IncidentReports;
use OCA\IntrusionDetection\Incident\ReportFormat;
use OCA\IntrusionDetection\Incident\ReportRenderer;
use OCA\IntrusionDetection\Incident\ReportSummary;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataDownloadResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * Every way to get an incident report: administrators only (see
 * AdminControllersTest), a recent password confirmation, a rate limit and
 * an audit log entry with who, about whom, which period and which form.
 */
class IncidentApiControllerTest extends TestCase {
	private const NOW = 1_800_000_000;

	private IL10N $l;
	private IncidentReportBuilder&MockObject $builder;
	private ReportRenderer&MockObject $renderer;
	private AuditLogger&MockObject $audit;
	private IncidentApiController $controller;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('admin');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$this->builder = $this->createMock(IncidentReportBuilder::class);
		$this->builder->method('build')->willReturnCallback(static fn (IncidentQuery $query, string $by): IncidentReport => new IncidentReport(
			$query, null, self::NOW, $by, 'https://cloud.example.org',
			new ReportSummary('Nothing.', [], null, null, null, [], [], null, [], [], ['entries' => 0, 'detections' => 0, 'enforced' => 0, 'observed' => 0]),
			[], [], [], false, IncidentReportBuilder::MAX_ENTRIES,
		));
		$this->renderer = $this->createMock(ReportRenderer::class);
		$this->renderer->method('json')->willReturn("{\"schemaVersion\":1}\n");
		$this->renderer->method('html')->willReturn('<!DOCTYPE html><html></html>');
		$this->renderer->method('filename')->willReturnCallback(static fn (IncidentReport $r, ReportFormat $f): string => 'incident-report.' . $f->extension());
		$this->audit = $this->createMock(AuditLogger::class);
		$this->controller = new IncidentApiController(
			$this->createMock(IRequest::class),
			$this->l,
			$session,
			new IncidentReports($this->builder, $this->renderer, $this->audit),
			$time,
		);
	}

	public function testEveryRouteIsAPostWithPasswordConfirmationAndARateLimit(): void {
		$routes = 0;
		foreach ((new \ReflectionClass(IncidentApiController::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			$route = $method->getAttributes(ApiRoute::class);
			if ($route === []) {
				continue;
			}
			$routes++;
			$this->assertSame('POST', $route[0]->getArguments()['verb'], $method->getName() . ' generates a report and is no GET');
			$this->assertCount(1, $method->getAttributes(PasswordConfirmationRequired::class), $method->getName());
			$this->assertCount(1, $method->getAttributes(UserRateLimit::class), $method->getName());
		}
		$this->assertSame(2, $routes);
	}

	public function testTheReportIsAuditedAndNotCached(): void {
		$this->audit->expects($this->once())->method('log')->with($this->stringContains('incident report'), [
			'subjectType' => 'user',
			'subject' => 'alice',
			'since' => gmdate('Y-m-d\TH:i:s\Z', self::NOW - 7 * 86400),
			'until' => gmdate('Y-m-d\TH:i:s\Z', self::NOW),
			'actor' => 'admin',
			'format' => 'screen',
		]);
		$response = $this->controller->report(' alice ');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame('alice', $response->getData()['subject']['value']);
		$this->assertSame('admin', $response->getData()['generatedBy']);
		$this->assertSame('no-store', $response->getHeaders()['Cache-Control']);
	}

	public function testExactlyOneSubject(): void {
		$this->builder->expects($this->never())->method('build');
		$this->audit->expects($this->never())->method('log');
		foreach ([['', ''], ['alice', '198.51.100.7']] as [$user, $address]) {
			$response = $this->controller->report($user, $address);
			$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
			$this->assertSame('subject', $response->getData()['param']);
		}
	}

	public function testAnInvalidPeriodIsExplainedAndNothingIsBuilt(): void {
		$this->builder->expects($this->never())->method('build');
		$this->audit->expects($this->never())->method('log');
		$response = $this->controller->report('', '198.51.100.7', self::NOW, self::NOW - 60);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame('range_order', $response->getData()['reason']);
		$this->assertSame('The start of the period must be before its end.', $response->getData()['message']);

		$this->assertSame('invalid_address', $this->controller->report('', 'not-an-ip')->getData()['reason']);
	}

	public function testDownloadsAreDocumentsThatAreNotCachedAndAudited(): void {
		$formats = [];
		$this->audit->expects($this->exactly(2))->method('log')->willReturnCallback(function (string $message, array $parameters) use (&$formats): void {
			$this->assertSame('198.51.100.7', $parameters['subject']);
			$this->assertSame('address', $parameters['subjectType']);
			$this->assertSame('admin', $parameters['actor']);
			$formats[] = $parameters['format'];
		});

		$json = $this->controller->download('json', '', '198.51.100.7', self::NOW - 3600, self::NOW);
		$this->assertInstanceOf(DataDownloadResponse::class, $json);
		$headers = $json->getHeaders();
		$this->assertSame('application/json; charset=utf-8', $headers['Content-Type']);
		$this->assertSame('attachment; filename=incident-report.json', $headers['Content-Disposition']);
		$this->assertSame('no-store', $headers['Cache-Control']);
		$this->assertSame('nosniff', $headers['X-Content-Type-Options']);
		$this->assertStringContainsString("default-src 'none'", $headers['Content-Security-Policy']);
		$this->assertSame("{\"schemaVersion\":1}\n", $json->render());

		$html = $this->controller->download('html', '', '198.51.100.7');
		$this->assertInstanceOf(DataDownloadResponse::class, $html);
		$this->assertSame('text/html; charset=utf-8', $html->getHeaders()['Content-Type']);
		$this->assertSame(['json', 'html'], $formats);
	}

	public function testAnUnknownDocumentKindIsRefused(): void {
		$this->audit->expects($this->never())->method('log');
		foreach (['pdf', 'screen', ''] as $output) {
			$response = $this->controller->download($output, 'alice');
			$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
			$this->assertSame('output', $response->getData()['param']);
		}
	}
}
