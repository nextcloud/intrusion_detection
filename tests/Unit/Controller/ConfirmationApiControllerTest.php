<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Admin\ConfirmationOverview;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\NoMethodPreset;
use OCA\IntrusionDetection\Controller\ConfirmationApiController;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * Setting what happens to every login that cannot be confirmed, at once:
 * behind password confirmation, and audited.
 */
class ConfirmationApiControllerTest extends TestCase {
	private NoMethodPreset&MockObject $preset;
	private AuditLogger&MockObject $audit;
	private ConfirmationOverview&MockObject $overview;
	private ConfirmationApiController $controller;

	protected function setUp(): void {
		parent::setUp();
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$this->preset = $this->createMock(NoMethodPreset::class);
		$this->audit = $this->createMock(AuditLogger::class);
		$this->overview = $this->createMock(ConfirmationOverview::class);
		$this->overview->method('policies')->willReturn([]);
		$this->controller = new ConfirmationApiController(
			$this->createMock(IRequest::class),
			Server::get(IFactory::class)->get('intrusion_detection', 'en'),
			$session,
			$this->overview,
			$this->createMock(ConfirmationCoverage::class),
			$this->preset,
			$this->audit,
		);
	}

	public function testThePresetNeedsPasswordConfirmation(): void {
		$this->assertCount(1, (new \ReflectionMethod(ConfirmationApiController::class, 'setPreset'))->getAttributes(PasswordConfirmationRequired::class));
	}

	public function testAChangeIsSavedAndAudited(): void {
		$this->preset->expects($this->once())->method('apply')->with('refuse')
			->willReturn(['step_up_no_method_protected_account' => 'refuse']);
		$this->preset->method('current')->willReturn('refuse');
		$this->audit->expects($this->once())->method('log')
			->with($this->stringContains('login confirmation'), $this->callback(static fn (array $p): bool => $p['preset'] === 'refuse'
				&& $p['actor'] === 'alice'
				&& str_contains((string)$p['change'], 'step_up_no_method_protected_account')));

		$response = $this->controller->setPreset('refuse');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(['preset' => 'refuse', 'policies' => []], $response->getData());
	}

	public function testNothingChangedIsNotAudited(): void {
		$this->preset->method('apply')->willReturn([]);
		$this->preset->method('current')->willReturn('recommended');
		$this->audit->expects($this->never())->method('log');
		$this->assertSame('recommended', $this->controller->setPreset('recommended')->getData()['preset']);
	}

	public function testCustomCannotBeSet(): void {
		$this->preset->method('apply')->willThrowException(new InvalidParamException('not_a_choice', ['param' => 'preset', 'choices' => 'recommended, refuse, allow']));
		$this->audit->expects($this->never())->method('log');
		$response = $this->controller->setPreset('custom');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame('preset', $response->getData()['param']);
	}
}
