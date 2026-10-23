<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Notification\MailReach;
use OCP\IConfig;
use OCP\IUser;
use OCP\Mail\IEmailValidator;
use OCP\Server;
use Test\TestCase;

class MailReachTest extends TestCase {
	private string $smtpMode = 'smtp';

	public function testOnlyAccountsWithAValidAddressOnAServerThatSendsMailCanBeReached(): void {
		$this->assertTrue($this->reach()->canReach($this->user('alice@example.com')));
		$this->assertTrue($this->reach()->hasAddress($this->user('alice@example.com')));
		$this->assertFalse($this->reach()->canReach($this->user('')), 'No email address');
		$this->assertFalse($this->reach()->hasAddress($this->user(null)));
		$this->assertFalse($this->reach()->canReach($this->user('not an address')));
		$this->assertFalse($this->reach()->hasAddress($this->user('not an address')));
		$this->smtpMode = 'null';
		$this->assertFalse($this->reach()->canReach($this->user('alice@example.com')), 'The server does not send mail');
		$this->assertTrue($this->reach()->hasAddress($this->user('alice@example.com')), 'It still has an address');
	}

	private function reach(): MailReach {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default): string => $key === 'mail_smtpmode' ? $this->smtpMode : $default);
		return new MailReach(Server::get(IEmailValidator::class), $config);
	}

	private function user(?string $address): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getEMailAddress')->willReturn($address);
		return $user;
	}
}
