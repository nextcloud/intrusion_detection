<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SetupCheck\AdminContactCheck;
use OCA\IntrusionDetection\SetupCheck\BruteForceProtectionCheck;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\LearningModeCheck;
use OCA\IntrusionDetection\SetupCheck\MailCheck;
use OCA\IntrusionDetection\SetupCheck\MemoryCacheCheck;
use OCA\IntrusionDetection\SetupCheck\ProblemCheck;
use OCA\IntrusionDetection\SetupCheck\ReverseProxyCheck;
use OCA\IntrusionDetection\SetupCheck\SharedAddressCheck;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
use OCP\IL10N;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The findings of the app's setup checks as cards with a fix under the
 * status banner, the most serious first.
 *
 * @psalm-import-type IntrusionDetectionProblem from ResponseDefinitions
 */
class SetupProblems implements IStatusContributor {
	/** @var list<class-string<ProblemCheck>> */
	public const CHECKS = [
		ReverseProxyCheck::class,
		BruteForceProtectionCheck::class,
		MailCheck::class,
		MemoryCacheCheck::class,
		TrapNameCollisionCheck::class,
		SharedAddressCheck::class,
		LearningModeCheck::class,
		UsersWithoutConfirmationCheck::class,
		AdminContactCheck::class,
	];

	private const ORDER = [Finding::LEVEL_ERROR => 0, Finding::LEVEL_WARNING => 1, Finding::LEVEL_INFO => 2];

	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function key(): string {
		return 'setup';
	}

	#[\Override]
	public function data(IL10N $l): ?array {
		return null;
	}

	#[\Override]
	public function problems(IL10N $l): array {
		$findings = [];
		foreach (self::CHECKS as $class) {
			try {
				$check = $this->container->get($class);
				if ($check instanceof ProblemCheck) {
					$finding = $check->finding($l);
					if ($finding !== null) {
						$findings[] = $finding;
					}
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection setup check {class} failed', ['class' => $class, 'exception' => $e]);
			}
		}
		usort($findings, static fn (Finding $a, Finding $b): int => self::ORDER[$a->level] <=> self::ORDER[$b->level]);
		return array_map(static fn (Finding $f): array => [
			'id' => $f->id,
			'level' => $f->level,
			'title' => $f->title,
			'text' => $f->text,
			'fix' => $f->fix,
			'url' => $f->url,
			'urlLabel' => $f->urlLabel,
		], $findings);
	}
}
