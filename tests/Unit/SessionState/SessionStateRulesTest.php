<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Session\Memory;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * Rules fail open, except the step-up rule while a step-up is pending.
 */
class SessionStateRulesTest extends TestCase {
	private SessionMarkers $state;

	protected function setUp(): void {
		parent::setUp();
		$this->state = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
	}

	public function testABrokenStepUpRuleBlocksWhileAStepUpIsPending(): void {
		$broken = $this->createMock(StepUpRule::class);
		$broken->method('check')->willThrowException(new \RuntimeException('database gone'));
		$rules = $this->rules([StepUpRule::class => $broken]);
		$target = RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/');

		$this->assertNull($rules->check($this->state, $target), 'Nothing pending: the request passes');
		$this->pending();
		$block = $rules->check($this->state, $target);
		$this->assertSame(StepUpRule::ERROR, $block?->error);
		$this->assertSame(StepUpRule::DAV_HEADER, $block->davHeader);
		$this->assertNull($block->redirectUrl);
	}

	public function testAStepUpRuleThatCannotBeLoadedBlocksWhileAStepUpIsPending(): void {
		$rules = $this->rules([]);
		$target = RequestTarget::dav('GET', '/');
		$this->assertNull($rules->check($this->state, $target));
		$this->pending();
		$this->assertSame(StepUpRule::ERROR, $rules->check($this->state, $target)?->error);
	}

	public function testOtherBrokenRulesLetTheRequestPass(): void {
		$broken = $this->createMock(PasswordChangeRule::class);
		$broken->method('check')->willThrowException(new \RuntimeException('broken'));
		$this->state->set(SessionMarkers::PASSWORD_CHANGE, ['uid' => 'alice', 'mode' => 'redirect', 'since' => 1]);
		$this->assertNull($this->rules([PasswordChangeRule::class => $broken], [PasswordChangeRule::class])->check($this->state, RequestTarget::dav('GET', '/')));
	}

	private function pending(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', StepUpState::PENDING, ['flagged_source'], 1, 2))->toArray());
	}

	/**
	 * @param array<string, object> $byClass the rules that load; any other throws
	 * @param list<class-string<\OCA\IntrusionDetection\SessionState\ISessionStateRule>> $classes
	 */
	private function rules(array $byClass, array $classes = [StepUpRule::class]): SessionStateRules {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): object => $byClass[$id] ?? throw new \RuntimeException('cannot build ' . $id));
		return new class($classes, $container, $this->createMock(LoggerInterface::class), new \OCA\IntrusionDetection\Login\RequestContext(), $this->createMock(\OCP\IRequest::class)) extends SessionStateRules {
			/**
			 * @param list<class-string<\OCA\IntrusionDetection\SessionState\ISessionStateRule>> $names
			 */
			public function __construct(
				private readonly array $names,
				ContainerInterface $container,
				LoggerInterface $logger,
				\OCA\IntrusionDetection\Login\RequestContext $context,
				\OCP\IRequest $request,
			) {
				parent::__construct($container, $logger, $context, $request);
			}

			protected function classes(): array {
				return $this->names;
			}
		};
	}
}
