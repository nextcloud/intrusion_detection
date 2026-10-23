<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Explain;

use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class TextRendererTest extends TestCase {
	private TextRenderer $renderer;

	protected function setUp(): void {
		parent::setUp();
		$this->renderer = new TextRenderer(new GlobalSettings());
	}

	/**
	 * @return list<array{int, string}>
	 */
	public static function durations(): array {
		return [
			[1, '1 second'],
			[59, '59 seconds'],
			[60, '1 minute'],
			[90, '90 seconds'],
			[600, '10 minutes'],
			[3600, '1 hour'],
			[5400, '90 minutes'],
			[14400, '4 hours'],
			[86400, '1 day'],
			[90000, '25 hours'],
			[604800, '7 days'],
		];
	}

	#[DataProvider('durations')]
	public function testADurationIsGivenInItsLargestWholeUnit(int $seconds, string $text): void {
		$this->assertSame($text, TextRenderer::duration($seconds, self::l()));
	}

	public function testValuesAreFormattedByTheirType(): void {
		$duration = new ParamDefinition('window', ParamType::Duration, 600);
		$this->assertSame('10 minutes', $this->renderer->format(600, $duration, self::l()));
		$this->assertSame('600', $this->renderer->format(600, null, self::l()), 'Only a duration parameter is a duration');
		$this->assertSame('on', $this->renderer->format(true, null, self::l()));
		$this->assertSame('off', $this->renderer->format(false, null, self::l()));
		$this->assertSame('none', $this->renderer->format([], null, self::l()));
		$this->assertSame('a, b', $this->renderer->format(['a', 'b'], null, self::l()));
		$this->assertSame('1.5', $this->renderer->format(1.5, null, self::l()));
		$this->assertSame('2', $this->renderer->format(2.0, null, self::l()));
		$this->assertSame('0.33', $this->renderer->format(1 / 3, null, self::l()));
		$this->assertSame('text', $this->renderer->format('text', null, self::l()));
	}

	public function testPlaceholdersAreFilledFromTheChecksParametersOrTheGlobalSettings(): void {
		$check = (new PasswordSpraying(new DateFormatter()))->definition();

		$this->assertSame(
			'10 minutes, 3600, 4 hours, {unknown}',
			$this->renderer->fill('{window}, {min_names}, {ban_duration_1}, {unknown}', ['window' => 600, 'min_names' => 3600, 'ban_duration_1' => 14400], self::l(), $check),
		);
		$this->assertSame('600 and on', $this->renderer->fill('{window} and {flag}', ['window' => 600, 'flag' => true], self::l()), 'Without a check, only global settings are typed');
	}

	private static function l(): IL10N {
		return Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}
}
