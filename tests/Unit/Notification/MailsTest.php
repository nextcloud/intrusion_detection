<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Notification\MailContent;
use OCA\IntrusionDetection\Notification\Mails;
use OCP\IUser;
use OCP\Mail\IEmailValidator;
use OCP\Mail\IMailer;
use OCP\Mail\IMessage;
use OCP\Server;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class MailsTest extends TestCase {
	public function testNobodyWithoutAnAddressIsMailed(): void {
		$mailer = $this->createMock(IMailer::class);
		$mailer->expects($this->never())->method('send');
		$mails = new Mails($mailer, Server::get(IEmailValidator::class), $this->createMock(LoggerInterface::class));
		$this->assertFalse($mails->send($this->user(null), $this->content()));
		$this->assertFalse($mails->send($this->user(''), $this->content()));
		$this->assertFalse($mails->send($this->user('not an address'), $this->content()));
	}

	public function testTheTemplateEscapesEverythingAndControlCharactersAreRemoved(): void {
		$sent = null;
		$mailer = $this->createMock(IMailer::class);
		$mailer->method('createEMailTemplate')->willReturnCallback(static fn (string $id, array $data) => Server::get(IMailer::class)->createEMailTemplate($id, $data));
		$message = $this->createMock(IMessage::class);
		$message->method('setTo')->willReturnSelf();
		$message->method('useTemplate')->willReturnCallback(function ($template) use (&$sent, $message) {
			$sent = $template;
			return $message;
		});
		$mailer->method('createMessage')->willReturn($message);
		$mailer->method('send')->willReturn([]);
		$mails = new Mails($mailer, Server::get(IEmailValidator::class), $this->createMock(LoggerInterface::class));

		$this->assertTrue($mails->send($this->user('alice@example.com'), new MailContent(
			templateId: 'intrusion_detection.test',
			subject: "Alert\r\nBcc: evil@example.com",
			heading: '<script>alert(1)</script>',
			paragraphs: ['The decoy "<b>backup</b>" was used.'],
			listItems: ["Blocked\x07 198.51.100.7"],
			buttonText: 'Open',
			buttonUrl: 'https://cloud.example.com/settings/admin/intrusion_detection',
		)));
		$this->assertNotNull($sent);
		$html = $sent->renderHtml();
		$this->assertStringNotContainsString('<script>', $html);
		$this->assertStringContainsString('&lt;script&gt;', $html);
		$this->assertStringNotContainsString('<b>backup</b>', $html);
		$this->assertStringNotContainsString("\x07", $sent->renderText());
		$this->assertStringNotContainsString("\n", $sent->renderSubject());
	}

	public function testAFailingMailServerIsLoggedNotThrown(): void {
		$mailer = $this->createMock(IMailer::class);
		$mailer->method('createEMailTemplate')->willThrowException(new \RuntimeException('down'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$mails = new Mails($mailer, Server::get(IEmailValidator::class), $logger);
		$this->assertFalse($mails->send($this->user('alice@example.com'), $this->content()));
	}

	public function testCleanCutsLongTexts(): void {
		$this->assertSame(Mails::MAX_TEXT, mb_strlen(Mails::clean(str_repeat('a', 5000))));
		$this->assertSame('a b', Mails::clean("a\n\tb"));
	}

	private function content(): MailContent {
		return new MailContent('intrusion_detection.test', 'Subject', 'Heading', ['Text']);
	}

	private function user(?string $email): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getEMailAddress')->willReturn($email);
		$user->method('getUID')->willReturn('alice');
		$user->method('getDisplayName')->willReturn('Alice');
		return $user;
	}
}
