<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Incident\InvalidIncidentQuery;
use OCA\IntrusionDetection\Learning\LearningLimitException;
use OCA\IntrusionDetection\Response\InvalidBanException;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Middleware;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;

/**
 * Turns the domain errors of the app's API into one answer: the status
 * that fits the error and the body {message, param, reason}, where
 * `message` is translated, `param` names the field it is about, if any,
 * and `reason` is machine-readable. Registered for the app's own
 * controllers only.
 *
 * Errors are always JSON unless the request asked for XML, so a client
 * that downloads a document reads an error the same way as any other.
 *
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
class ApiErrorMiddleware extends Middleware {
	public function __construct(
		private readonly IRequest $request,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function afterException(Controller $controller, string $methodName, \Exception $exception): Response {
		$error = $controller instanceof OCSController ? $this->explain($exception) : null;
		if ($error === null) {
			throw $exception;
		}
		[$status, $body] = $error;
		$format = $this->request->getFormat();
		return $controller->buildResponse(new DataResponse($body, $status), $format !== null && $controller->isResponderRegistered($format) ? $format : 'json');
	}

	/**
	 * @return array{0: int, 1: IntrusionDetectionError}|null
	 */
	private function explain(\Exception $e): ?array {
		return match (true) {
			$e instanceof InvalidParamException => [Http::STATUS_BAD_REQUEST, self::body($e->describe($this->l), isset($e->details['param']) ? (string)$e->details['param'] : null, $e->reason)],
			$e instanceof InvalidIncidentQuery => [Http::STATUS_BAD_REQUEST, self::body($e->describe($this->l), $e->param(), $e->reason)],
			$e instanceof LearningLimitException => [Http::STATUS_BAD_REQUEST, self::body($e->describe($this->l), 'days', 'learning_limit')],
			$e instanceof InvalidBanException => [Http::STATUS_BAD_REQUEST, self::body($e->describe($this->l), $e->param(), $e->reason())],
			$e instanceof ApprovalException => [match ($e->reason) {
				ApprovalException::NOT_FOUND => Http::STATUS_NOT_FOUND,
				ApprovalException::REQUESTER, ApprovalException::SUBJECT, ApprovalException::NOT_ADMIN, ApprovalException::UNCONFIRMED, ApprovalException::NOT_PROVEN,
				ApprovalException::HELD, ApprovalException::HELD_NO_APPROVER => Http::STATUS_FORBIDDEN,
				ApprovalException::TOO_MANY => Http::STATUS_TOO_MANY_REQUESTS,
				default => Http::STATUS_BAD_REQUEST,
			}, self::body($e->describe($this->l), null, $e->reason)],
			$e instanceof AnswerException => [match ($e->reason) {
				AnswerException::NOT_FOUND => Http::STATUS_NOT_FOUND,
				AnswerException::NOT_ASKED => Http::STATUS_BAD_REQUEST,
				AnswerException::ANSWERED => Http::STATUS_CONFLICT,
				default => Http::STATUS_FORBIDDEN,
			}, self::body($e->describe($this->l), null, $e->reason)],
			$e instanceof OCSNotFoundException => [Http::STATUS_NOT_FOUND, self::body($e->getMessage(), null, 'not_found')],
			default => null,
		};
	}

	/**
	 * @return IntrusionDetectionError
	 */
	private static function body(string $message, ?string $param, string $reason): array {
		return ['message' => $message, 'param' => $param, 'reason' => $reason];
	}
}
