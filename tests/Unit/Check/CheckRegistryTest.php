<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCP\Config\Lexicon\Entry;
use OCP\L10N\IFactory;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * The registry is the single source of truth: the lexicon, the texts and the
 * settings must all agree with it.
 */
class CheckRegistryTest extends TestCase {
	private CheckRegistry $registry;

	protected function setUp(): void {
		parent::setUp();
		// Checks are built by the real container, as their narratives have dependencies.
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => Server::get($class));
		$this->registry = new CheckRegistry($container);
	}

	public function testEveryCheckClassIsRegisteredOnceWithAUniqueId(): void {
		$this->assertCount(count(CheckRegistry::CHECKS), $this->registry->all());
		$this->assertCount(count(CheckRegistry::CHECKS), array_unique(CheckRegistry::CHECKS));
	}

	public function testEveryCheckHasCompleteTexts(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		foreach ($this->registry->all() as $check) {
			foreach ($check->texts($l)->toArray() as $field => $text) {
				$this->assertNotSame('', trim($text), $check->id . ' has no ' . $field . ' text');
			}
		}
	}

	public function testPlaceholdersInDecideTextsExist(): void {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		foreach ($this->registry->all() as $check) {
			preg_match_all('/\{([a-z][a-z0-9_]*)\}/', $check->texts($l)->decides, $m);
			foreach ($m[1] as $name) {
				$this->assertTrue(
					$check->hasParam($name) || (new GlobalSettings())->get($name) !== null,
					$check->id . ' refers to an unknown setting {' . $name . '}',
				);
			}
		}
	}

	public function testLexiconHasOneEntryPerSettingWithTheSameDefault(): void {
		$entries = [];
		foreach ((new Lexicon())->getAppConfigs() as $entry) {
			/** @var Entry $entry */
			$this->assertArrayNotHasKey($entry->getKey(), $entries, 'Duplicate lexicon key ' . $entry->getKey());
			$entries[$entry->getKey()] = $entry;
		}
		foreach ((new GlobalSettings())->all() as $name => $definition) {
			$this->assertArrayHasKey($name, $entries);
			$this->assertSame($definition->type->valueType(), $entries[$name]->getValueType());
		}
		foreach ($this->registry->all() as $check) {
			$this->assertArrayHasKey(Keys::mode($check->id), $entries);
			$this->assertArrayHasKey(Keys::responses($check->id), $entries);
			$this->assertSame($check->defaultMode->value, $entries[Keys::mode($check->id)]->getDefault(\OCP\Config\Lexicon\Preset::NONE));
			foreach ($check->params as $param) {
				$key = Keys::param($check->id, $param->name);
				$this->assertArrayHasKey($key, $entries);
				$this->assertSame($param->type->valueType(), $entries[$key]->getValueType());
			}
		}
	}

	public function testTheRequiredPasswordChangeIsADeclaredUserSetting(): void {
		$entries = [];
		foreach ((new Lexicon())->getUserConfigs() as $entry) {
			$entries[$entry->getKey()] = $entry;
		}
		$this->assertArrayHasKey(PasswordChangeFlag::USER_KEY, $entries);
		$this->assertSame('0', $entries[PasswordChangeFlag::USER_KEY]->getDefault(\OCP\Config\Lexicon\Preset::NONE), 'Stored as a string');
		$this->assertSame(\OCP\Config\ValueType::INT, $entries[PasswordChangeFlag::USER_KEY]->getValueType());
	}

	public function testConfigKeysAreValidAndShortEnough(): void {
		foreach ((new Lexicon())->getAppConfigs() as $entry) {
			$this->assertMatchesRegularExpression('/^[a-z0-9_]+$/', $entry->getKey());
			$this->assertLessThanOrEqual(64, strlen($entry->getKey()), $entry->getKey() . ' is too long for oc_appconfig');
		}
	}

	public function testGlobalSettingsDoNotUseKeysCoreReservesForEveryApp(): void {
		foreach (['enabled', 'installed_version', 'types', 'groups'] as $reserved) {
			$this->assertArrayNotHasKey($reserved, (new GlobalSettings())->all());
		}
	}

	public function testSprayingCountsNoFurtherBackThanAttemptsAreKept(): void {
		$this->assertLessThanOrEqual(AttemptRecorder::RETENTION, $this->registry->get(PasswordSpraying::ID)->param('window')->max);
	}

	public function testDefaultResponsesAreAllowedResponses(): void {
		foreach ($this->registry->all() as $check) {
			foreach ($check->defaultResponses as $response) {
				$this->assertTrue($check->allowsResponse($response), $check->id . ': ' . $response->value);
			}
		}
	}

	public function testResponseOrderPutsBlocksFirstAndNotificationsLast(): void {
		$this->assertLessThan(ResponseType::KillSession->order(), ResponseType::Ban->order());
		foreach (ResponseType::cases() as $response) {
			if (!$response->isNotification()) {
				$this->assertLessThan(ResponseType::NotifyAdmin->order(), $response->order());
			}
		}
	}
}
