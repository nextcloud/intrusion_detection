<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Takeover;

use OCA\IntrusionDetection\Check\Checks\AccountTakeover\AccountTakeover;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Response\Handlers\LockLinkHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCP\IDateTimeFormatter;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

/**
 * The lock link response: only for email changes, once per detection, and
 * the narrative says why nothing was sent.
 */
class LockLinkHandlerTest extends TestCase {
	public function testWithoutAnEmailChangeNothingIsSent(): void {
		$links = $this->createMock(LockLinks::class);
		$links->expects($this->never())->method('send');
		$outcome = $this->handler($links)->apply($this->context(['emailChangeId' => null]));
		$this->assertSame(LockLinkHandler::NOTE_NO_EMAIL_CHANGE, $outcome->note);
	}

	public function testTheOutcomesOfSending(): void {
		$links = $this->createMock(LockLinks::class);
		$links->method('send')->willReturnOnConsecutiveCalls(
			['state' => LockLinks::SENT, 'sentTo' => 'o***@example.com', 'link' => 5],
			['state' => LockLinks::ALREADY_SENT],
			['state' => LockLinks::NO_PREVIOUS_ADDRESS],
			['state' => LockLinks::MAIL_FAILED, 'sentTo' => 'o***@example.com'],
		);
		$handler = $this->handler($links);
		$context = $this->context(['emailChangeId' => 3]);

		$sent = $handler->apply($context);
		$this->assertTrue($sent->enforced);
		$this->assertSame(['sentTo' => 'o***@example.com', 'link' => 5], $sent->ref, 'Identifiers only, never the token');
		$this->assertSame(ResponseOutcome::NOTE_NOTHING_TO_DO, $handler->apply($context)->note);
		$this->assertSame(LockLinks::NO_PREVIOUS_ADDRESS, $handler->apply($context)->note);
		$this->assertSame(LockLinks::MAIL_FAILED, $handler->apply($context)->note);
	}

	public function testTheNarrative(): void {
		$handler = $this->handler($this->createMock(LockLinks::class));
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$dates = DateFormatter::using($this->createMock(IDateTimeFormatter::class));
		$this->assertSame(['A one-time link to lock the account was emailed to the previous address o***@example.com. It works for 7 days.'], $handler->describeAction(['type' => 'lock_link', 'enforced' => true, 'ref' => ['sentTo' => 'o***@example.com']], $l, $dates));
		$this->assertSame(['No lock link was sent: the account had no email address before the change.'], $handler->describeAction(['type' => 'lock_link', 'enforced' => true, 'note' => LockLinks::NO_PREVIOUS_ADDRESS], $l, $dates));
		$this->assertSame(['No lock link was sent: the email address was not changed.'], $handler->describeAction(['type' => 'lock_link', 'enforced' => true, 'note' => LockLinkHandler::NOTE_NO_EMAIL_CHANGE], $l, $dates));
	}

	private function handler(LockLinks $links): LockLinkHandler {
		$users = $this->createMock(IUserManager::class);
		$users->method('get')->willReturn($this->createMock(IUser::class));
		return new LockLinkHandler($links, $users);
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	private function context(array $facts): ResponseContext {
		$detection = new Detection();
		$detection->setId(42);
		$detection->setExplanationData(['facts' => $facts]);
		return new ResponseContext(new DetectionDraft(AccountTakeover::ID, uid: 'alice', facts: $facts), $detection, (new AccountTakeover(DateFormatter::using($this->createMock(IDateTimeFormatter::class))))->definition(), true);
	}
}
