<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Risk;

use OCA\IntrusionDetection\Risk\AttackTools;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class AttackToolsTest extends TestCase {
	/**
	 * @return array<string, array{string, ?string}>
	 */
	public static function userAgents(): array {
		return [
			'hydra' => ['Mozilla/4.0 (Hydra)', 'hydra'],
			'medusa' => ['Medusa v2.2', 'medusa'],
			'ncrack' => ['ncrack/0.7', 'ncrack'],
			'nikto' => ['Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)', 'nikto'],
			'sqlmap' => ['sqlmap/1.7.2#stable (https://sqlmap.org)', 'sqlmap'],
			'zgrab' => ['Mozilla/5.0 zgrab/0.x', 'zgrab'],
			'masscan' => ['masscan/1.3 (https://github.com/robertdavidgraham/masscan)', 'masscan'],
			'nmap' => ['Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)', 'nmap'],
			'python-requests' => ['python-requests/2.31.0', 'python-requests'],
			'go' => ['Go-http-client/1.1', 'go-http-client'],
			'curl' => ['curl/8.4.0', 'curl'],
			'wget' => ['Wget/1.21.4', 'wget'],
			'perl' => ['libwww-perl/6.72', 'libwww-perl'],
			'java' => ['Java/17.0.2', 'java'],
			'Firefox' => ['Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', null],
			'desktop client' => ['Mozilla/5.0 (Linux) mirall/3.14.1 (Nextcloud, ubuntu-6.8.0 ClientArchitecture: x86_64 OsArchitecture: x86_64)', null],
			'Android client' => ['Mozilla/5.0 (Android) Nextcloud-android/3.29.0', null],
			'a word containing a tool' => ['Mozilla/5.0 (Macintosh) MyCurlyApp/1.0 javascript/1', null],
			'empty' => ['', null],
		];
	}

	#[DataProvider('userAgents')]
	public function testTheBuiltInListRecognisesToolsAndNotBrowsers(string $userAgent, ?string $tool): void {
		$this->assertSame($tool, (new AttackTools())->match($userAgent));
	}
}
