<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\CoreHooks;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\SetupCheck\CoreHooksCheck;
use OCP\IConfig;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

/**
 * On a server without the APIs the app hooks into, the checks that need
 * them are unavailable and a setup check says what is missing, instead of
 * the app looking configured while it protects nothing.
 */
class CoreHooksTest extends TestCase {
	public function testThisServerHasEveryHook(): void {
		$this->assertSame([], $this->hooks([])->missing());
	}

	public function testAMissingHookMakesItsChecksUnavailableAndIsNamed(): void {
		$hooks = $this->hooks(['OCP\\AppFramework\\Bootstrap\\IRegistrationContext::registerRequestGuard', 'OCP\\Security\\Events\\PasswordResetRequestedEvent']);
		$this->assertSame([CoreHooks::REQUEST_GUARDS, CoreHooks::RESET_EVENT], $hooks->missing());

		$prerequisites = new Prerequisites($this->createMock(Caches::class), $this->createMock(IConfig::class), $hooks);
		$this->assertFalse($prerequisites->isMet(Requirement::RequestGuards));
		$this->assertFalse($prerequisites->isMet(Requirement::ResetEvent));
		$this->assertTrue($prerequisites->isMet(Requirement::ShareAccessEvent));

		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$finding = (new CoreHooksCheck($this->createMock(IL10N::class), $this->createMock(AdminLinks::class), $hooks))->finding($l);
		$this->assertNotNull($finding);
		$this->assertSame('error', $finding->level);
		$this->assertStringContainsString('blocks, blocklists, trap URLs and injection probes are not enforced', $finding->text);
		$this->assertStringContainsString('password reset requests', $finding->text);
	}

	/**
	 * @param list<string> $absent what this server is made to lack
	 */
	private function hooks(array $absent): CoreHooks {
		return new class($absent) extends CoreHooks {
			/**
			 * @param list<string> $absent
			 */
			public function __construct(
				private array $absent,
			) {
			}

			protected function exists(string $name): bool {
				return !in_array($name, $this->absent, true) && parent::exists($name);
			}
		};
	}
}
