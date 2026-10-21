<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Incident;

use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\InvalidIncidentQuery;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class IncidentQueryTest extends TestCase {
	private const NOW = 1_800_000_000;

	public function testTheDefaultPeriodIsTheSevenDaysBeforeNow(): void {
		$query = IncidentQuery::forUser(' alice ', null, null, self::NOW);
		$this->assertTrue($query->isUser());
		$this->assertSame('alice', $query->uid);
		$this->assertNull($query->address);
		$this->assertSame(self::NOW, $query->until);
		$this->assertSame(self::NOW - 7 * 86400, $query->since);

		$ending = IncidentQuery::forUser('alice', null, self::NOW - 86400, self::NOW);
		$this->assertSame(self::NOW - 8 * 86400, $ending->since);
	}

	public function testAddressesAreNormalised(): void {
		$query = IncidentQuery::forAddress('2001:DB8:1:2::7', self::NOW - 3600, self::NOW, self::NOW);
		$this->assertFalse($query->isUser());
		$this->assertNull($query->uid);
		$this->assertSame('2001:db8:1:2::7', $query->subject());
		$this->assertSame('2001:db8:1:2::/64', $query->address?->netKey);

		$this->assertSame('198.51.100.7', IncidentQuery::forAddress('::ffff:198.51.100.7', null, null, self::NOW)->subject());
	}

	public function testTheLimitIsSetByTheBuilder(): void {
		$query = IncidentQuery::forUser('alice', null, null, self::NOW);
		$limited = $query->withLimit(2001);
		$this->assertSame(2001, $limited->limit);
		$this->assertSame($query->since, $limited->since);
		$this->assertSame(1, $query->withLimit(0)->limit);
	}

	/**
	 * @return array<string, array{callable(): IncidentQuery, string}>
	 */
	public static function invalid(): array {
		return [
			'empty account' => [static fn () => IncidentQuery::forUser('  ', null, null, self::NOW), InvalidIncidentQuery::INVALID_USER],
			'control character' => [static fn () => IncidentQuery::forUser("alice\nbob", null, null, self::NOW), InvalidIncidentQuery::INVALID_USER],
			'too long' => [static fn () => IncidentQuery::forUser(str_repeat('a', 65), null, null, self::NOW), InvalidIncidentQuery::INVALID_USER],
			'not an address' => [static fn () => IncidentQuery::forAddress('alice', null, null, self::NOW), InvalidIncidentQuery::INVALID_ADDRESS],
			'a network' => [static fn () => IncidentQuery::forAddress('198.51.100.0/24', null, null, self::NOW), InvalidIncidentQuery::INVALID_ADDRESS],
			'start after end' => [static fn () => IncidentQuery::forUser('alice', self::NOW, self::NOW - 1, self::NOW), InvalidIncidentQuery::RANGE_ORDER],
			'empty period' => [static fn () => IncidentQuery::forUser('alice', self::NOW, self::NOW, self::NOW), InvalidIncidentQuery::RANGE_ORDER],
			'longer than 90 days' => [static fn () => IncidentQuery::forAddress('198.51.100.7', self::NOW - 90 * 86400 - 1, self::NOW, self::NOW), InvalidIncidentQuery::RANGE_TOO_LONG],
			'negative' => [static fn () => IncidentQuery::forUser('alice', -5, 10, self::NOW), InvalidIncidentQuery::INVALID_RANGE],
		];
	}

	/**
	 * @param callable(): IncidentQuery $build
	 */
	#[DataProvider('invalid')]
	public function testInvalidInputIsRefusedWithAReason(callable $build, string $reason): void {
		try {
			$build();
			$this->fail('The query must be refused');
		} catch (InvalidIncidentQuery $e) {
			$this->assertSame($reason, $e->reason);
			$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
			$this->assertNotSame('', $e->describe($l));
			$this->assertContains($e->param(), ['user', 'address', 'since', 'subject']);
		}
	}

	public function testExactlyNinetyDaysAreAllowed(): void {
		$query = IncidentQuery::forAddress('198.51.100.7', self::NOW - 90 * 86400, self::NOW, self::NOW);
		$this->assertSame(90 * 86400, $query->until - $query->since);
	}
}
