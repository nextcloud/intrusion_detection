<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OCA\IntrusionDetection\Admin\SetupProblems;
use OCA\IntrusionDetection\SetupCheck\BruteForceProtectionCheck;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\MailCheck;
use OCA\IntrusionDetection\SetupCheck\MemoryCacheCheck;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCP\IL10N;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SetupProblemsTest extends TestCase {
	public function testFindingsBecomeProblemCardsTheMostSeriousFirst(): void {
		$l = $this->createMock(IL10N::class);
		$checks = [
			MailCheck::class => new Finding('mail_missing', Finding::LEVEL_WARNING, 'Mail', 'No mail.', 'Set it up.', 'https://docs.example.com/mail', 'Docs'),
			MemoryCacheCheck::class => new Finding('memory_cache_missing', Finding::LEVEL_INFO, 'Cache', 'No cache.', 'Add one.'),
			TrapNameCollisionCheck::class => new Finding('trap_name_collision', Finding::LEVEL_ERROR, 'Names', 'Taken.', 'Remove them.', '#decoys', 'Open'),
		];
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use ($checks) {
			if ($class === BruteForceProtectionCheck::class) {
				throw new \RuntimeException('broken check');
			}
			$check = $this->createMock($class);
			$check->method('finding')->willReturn($checks[$class] ?? null);
			return $check;
		});
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');

		$contributor = new SetupProblems($container, $logger);
		$this->assertSame('setup', $contributor->key());
		$this->assertNull($contributor->data($l));
		$problems = $contributor->problems($l);
		$this->assertSame(['trap_name_collision', 'mail_missing', 'memory_cache_missing'], array_column($problems, 'id'));
		$this->assertSame(['id' => 'trap_name_collision', 'level' => 'error', 'title' => 'Names', 'text' => 'Taken.', 'fix' => 'Remove them.', 'url' => '#decoys', 'urlLabel' => 'Open'], $problems[0]);
	}
}
