<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Middleware;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Incident\InvalidIncidentQuery;
use OCA\IntrusionDetection\Learning\LearningLimitException;
use OCA\IntrusionDetection\Middleware\ApiErrorMiddleware;
use OCA\IntrusionDetection\Response\BanRefusedException;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class ApiErrorMiddlewareTest extends TestCase {
	/**
	 * @return array<string, array{\Exception, int, ?string, string}>
	 */
	public static function errors(): array {
		return [
			'invalid value' => [new InvalidParamException('too_small', ['param' => 'window', 'min' => 60]), Http::STATUS_BAD_REQUEST, 'window', 'too_small'],
			'invalid value of no field' => [new InvalidParamException('unknown_mode'), Http::STATUS_BAD_REQUEST, null, 'unknown_mode'],
			'incident query' => [new InvalidIncidentQuery(InvalidIncidentQuery::INVALID_ADDRESS), Http::STATUS_BAD_REQUEST, 'address', 'invalid_address'],
			'learning limit' => [new LearningLimitException(1_800_000_000, 1_797_408_000), Http::STATUS_BAD_REQUEST, 'days', 'learning_limit'],
			'never blocked' => [new BanRefusedException('198.51.100.0/24'), Http::STATUS_BAD_REQUEST, 'target', 'invalid_target'],
			'no such approval' => [new ApprovalException(ApprovalException::NOT_FOUND), Http::STATUS_NOT_FOUND, null, 'not_found'],
			'own approval' => [new ApprovalException(ApprovalException::REQUESTER), Http::STATUS_FORBIDDEN, null, 'requester'],
			'unconfirmed approver' => [new ApprovalException(ApprovalException::UNCONFIRMED), Http::STATUS_FORBIDDEN, null, 'unconfirmed'],
			'decided approval' => [new ApprovalException(ApprovalException::NOT_PENDING), Http::STATUS_BAD_REQUEST, null, 'not_pending'],
			'no such event' => [new AnswerException(AnswerException::NOT_FOUND), Http::STATUS_NOT_FOUND, null, 'not_found'],
			'answered event' => [new AnswerException(AnswerException::ANSWERED), Http::STATUS_CONFLICT, null, 'answered'],
			'event that asks nothing' => [new AnswerException(AnswerException::NOT_ASKED), Http::STATUS_BAD_REQUEST, null, 'not_asked'],
			'answer from this session' => [new AnswerException(AnswerException::SESSION_NOT_ALLOWED, yes: true), Http::STATUS_FORBIDDEN, null, 'session_not_allowed'],
			'not found' => [new OCSNotFoundException('This block does not exist (any more).'), Http::STATUS_NOT_FOUND, null, 'not_found'],
		];
	}

	#[DataProvider('errors')]
	public function testDomainErrorsHaveOneShape(\Exception $error, int $status, ?string $param, string $reason): void {
		$response = $this->middleware('json')->afterException($this->controller('json'), 'call', $error);
		$this->assertInstanceOf(DataResponse::class, $response);
		$this->assertSame($status, $response->getStatus());
		$this->assertSame(['message', 'param', 'reason'], array_keys($response->getData()));
		$this->assertSame([$param, $reason], [$response->getData()['param'], $response->getData()['reason']]);
		$this->assertNotSame('', $response->getData()['message']);
	}

	public function testTheMessagesAreTranslatedTexts(): void {
		$answer = fn (\Exception $e): string => $this->middleware('json')->afterException($this->controller('json'), 'call', $e)->getData()['message'];
		$this->assertSame('"window" must be at least 60.', $answer(new InvalidParamException('too_small', ['param' => 'window', 'min' => 60])));
		$this->assertSame('This check cannot run on this server: Needs email to be configured.', $answer(new InvalidParamException('mode_unavailable', ['why' => 'mail'])));
		$this->assertStringStartsWith('For your safety, "Yes, it was me" can only be answered in a browser', $answer(new AnswerException(AnswerException::SESSION_NOT_ALLOWED, yes: true)));
		$this->assertStringStartsWith('For your safety, "No, it was not me" cannot be answered', $answer(new AnswerException(AnswerException::SESSION_NOT_ALLOWED)));
		$this->assertStringStartsWith('Learning mode lasts at most 30 days in all', $answer(new LearningLimitException(1_800_000_000, 1_797_408_000)));
		$this->assertSame('This block does not exist (any more).', $answer(new OCSNotFoundException('This block does not exist (any more).')));
	}

	public function testAnErrorOfADownloadIsJson(): void {
		$controller = $this->controller('json');
		$controller->expects($this->once())->method('buildResponse')->with($this->isInstanceOf(DataResponse::class), 'json');
		$this->middleware('octet-stream')->afterException($controller, 'download', new InvalidIncidentQuery(InvalidIncidentQuery::SUBJECT));
	}

	public function testOtherErrorsAreLeftToCore(): void {
		$error = new \RuntimeException('database gone');
		$this->expectExceptionObject($error);
		$this->middleware('json')->afterException($this->controller('json'), 'call', $error);
	}

	public function testPagesAreLeftAlone(): void {
		$error = new InvalidParamException('unknown_mode');
		$this->expectExceptionObject($error);
		$this->middleware('json')->afterException($this->createMock(Controller::class), 'call', $error);
	}

	private function middleware(string $format): ApiErrorMiddleware {
		$request = $this->createMock(IRequest::class);
		$request->method('getFormat')->willReturn($format);
		return new ApiErrorMiddleware($request, Server::get(IFactory::class)->get('intrusion_detection', 'en'));
	}

	/**
	 * An OCS controller that answers in JSON and returns the data response as it is.
	 */
	private function controller(string $format): OCSController {
		$controller = $this->createMock(OCSController::class);
		$controller->method('buildResponse')->willReturnArgument(0);
		$controller->method('isResponderRegistered')->willReturnCallback(static fn (string $f): bool => $f === $format || $f === 'xml');
		return $controller;
	}
}
