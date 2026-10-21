<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Notification;

use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class AppPasswordNameTest extends TestCase {
	/**
	 * @return array<string, array{?string, ?string}>
	 */
	public static function names(): array {
		return [
			'a name the user chose' => ['Thunderbird', 'Thunderbird'],
			'versions stay' => ['Thunderbird 115.3 on laptop', 'Thunderbird 115.3 on laptop'],
			'a link' => ['Restore at https://evil.example/login', 'Restore at https evil example/login'],
			'www' => ['Go to www.evil.example now', 'Go to evil example now'],
			'a bare domain' => ['Call evil-support.com', 'Call evil-support com'],
			'a full-width dot' => ['evil．example', 'evil example'],
			'an email address' => ['help@evil.example', 'help evil example'],
			'quotes' => ['My "work" phone', "My 'work' phone"],
			'control and bidi characters' => ["Phone\x07\u{202E}moc.live", 'Phone moc live'],
			'too long' => [str_repeat('abcdefghij', 6), str_repeat('abcdefghij', 3) . 'abcdefghi…'],
			'nothing left' => ["\x00\u{200B}", null],
			'none' => [null, null],
		];
	}

	#[DataProvider('names')]
	public function testTheNameIsShownCleanedAndNeverAsALink(?string $name, ?string $shown): void {
		$this->assertSame($shown, UserMessages::appPasswordName($name));
		if ($shown !== null) {
			$this->assertLessThanOrEqual(UserMessages::MAX_APP_PASSWORD_NAME, mb_strlen($shown));
			$this->assertDoesNotMatchRegularExpression('#://|www\.|\.[a-z]{2}#i', $shown);
		}
	}

	public function testTheDeviceIsAddedWhereTheNameStandsForOne(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->assertSame('"Thunderbird"', UserMessages::appPassword('Thunderbird', $l));
		$this->assertSame('"Mozilla/5.0 (Windows NT 10.0) Firefox/1…" (Firefox on Windows)', UserMessages::appPassword('Mozilla/5.0 (Windows NT 10.0) Firefox/131.0 restore at https://evil.example', $l));
		$this->assertNull(UserMessages::appPassword("\x07", $l));
	}
}
