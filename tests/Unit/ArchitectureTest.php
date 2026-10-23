<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit;

use Test\TestCase;

/**
 * The dependency direction between the namespaces of lib/, as ARCHITECTURE.md
 * describes it. A namespace may use its own layer and the layers below it.
 * A dependency is any class of the app a file names in code: imports,
 * qualified names and fully qualified names; comments do not count.
 */
class ArchitectureTest extends TestCase {
	private const APP = 'OCA\\IntrusionDetection\\';
	private const LIB = __DIR__ . '/../../lib';

	/** Bottom to top */
	private const LAYERS = [
		'kernel' => ['Definition', 'Net', 'Crypto', 'Audit', 'Http', 'ResponseDefinitions', 'Sensitive', 'Cache', 'State'],
		'storage' => ['Db', 'Config'],
		'platform' => ['Check', 'Configure', 'Detection', 'Response', 'Signal', 'Explain', 'Event', 'Notification', 'Login'],
		'features' => [
			'Check\\Checks',
			'Address', 'AdminChange', 'Blocklist', 'Breach', 'Confirm', 'Decoy', 'Export', 'Guide', 'Incident', 'KnownDevice',
			'Learning', 'LoginHistory', 'OpenMetrics', 'Privacy', 'Risk', 'SessionState', 'Share', 'StaleCredential', 'Takeover',
			'Traps', 'TrustedNetwork', 'WasThisYou',
		],
		'pages' => ['Admin', 'Personal'],
		'adapters' => [
			'AppInfo', 'BackgroundJob', 'Command', 'Controller', 'Dashboard', 'Dav', 'Guard', 'Listener', 'Middleware',
			'Migration', 'Perf', 'Repair', 'Settings', 'SetupCheck',
		],
	];

	/** Generic namespaces, which must not name a check */
	private const PLATFORM = ['Definition', 'Net', 'Crypto', 'Audit', 'Http', 'ResponseDefinitions', 'Sensitive', 'Cache', 'State', 'Db', 'Config',
		'Check', 'Configure', 'Detection', 'Response', 'Signal', 'Explain', 'Event', 'Notification', 'Login'];

	/**
	 * Today's dependencies that point upward. Entries may only be removed.
	 *
	 * @var array<string, list<string>>
	 */
	private const ALLOWED_UPWARD = [
		// SETUP_CHECKS stays in Application so that registering loads no class; the status runs the ProblemChecks
		// and shows the guard timings.
		'Admin' => ['AppInfo', 'Perf', 'SetupCheck'],
		// Watched settings are described with the admin page's global settings presenter.
		'AdminChange' => ['Admin'],
		// CheckRegistry::CHECKS is the one list of all checks.
		'Check' => ['Check\\Checks'],
		// Check names live in Admin (feature slices).
		'Check\\Checks' => ['Admin'],
		// The risk scorer adds to detections and narratives (pipeline).
		'Detection' => ['Risk'],
		'Explain' => ['Risk'],
		// Incident reports reuse the admin page's detection presenter and check names.
		'Incident' => ['Admin'],
		// Feature notifications live in Notification (feature slices).
		'Notification' => ['Admin', 'BackgroundJob', 'Blocklist', 'Check\\Checks', 'KnownDevice', 'Learning', 'Share', 'WasThisYou'],
		'OpenMetrics' => ['Perf'],
		// The privacy cleanup schedules its job by class.
		'Privacy' => ['BackgroundJob'],
		// Handlers of feature responses use their feature's services (feature slices).
		'Response' => ['Address', 'Confirm', 'Share', 'Takeover'],
	];

	/**
	 * Generic files that still name a check, and why. Entries may only be removed.
	 *
	 * @var array<string, string>
	 */
	private const NAMES_A_CHECK = [
		'Check/CheckRegistry.php' => 'the list of all checks',
		'Notification/Notifier.php' => 'approval notifications name the actor like the admin-change check (feature slices)',
	];

	/** @var array<string, array<string, list<string>>>|null unit => used unit => files */
	private static ?array $dependencies = null;

	public function testEveryNamespaceHasALayer(): void {
		$placed = array_merge(...array_values(self::LAYERS));
		$this->assertSame(count($placed), count(array_unique($placed)), 'a namespace is in two layers');
		$units = array_keys(self::dependencies());
		$this->assertSame([], array_values(array_diff($units, $placed)), 'add new namespaces to a layer in LAYERS and ARCHITECTURE.md');
		$this->assertSame([], array_values(array_diff($placed, $units)), 'remove namespaces that no longer exist');
	}

	public function testDependenciesPointDownwardExceptTheListedOnes(): void {
		$upward = [];
		$files = [];
		foreach (self::dependencies() as $from => $tos) {
			foreach ($tos as $to => $where) {
				if (self::layer($to) > self::layer($from)) {
					$upward[$from][] = $to;
					$files[$from . ' -> ' . $to] = $where;
				}
			}
		}
		$new = [];
		$stale = [];
		foreach ($upward as $from => $tos) {
			foreach (array_diff($tos, self::ALLOWED_UPWARD[$from] ?? []) as $to) {
				$new[] = $from . ' -> ' . $to . ' (' . implode(', ', $files[$from . ' -> ' . $to]) . ')';
			}
		}
		foreach (self::ALLOWED_UPWARD as $from => $tos) {
			foreach (array_diff($tos, $upward[$from] ?? []) as $to) {
				$stale[] = $from . ' -> ' . $to;
			}
		}
		$this->assertSame([], $new, 'dependencies that point upward; turn them around, or move the class');
		$this->assertSame([], $stale, 'fixed: remove them from ALLOWED_UPWARD');
	}

	public function testTheDefinitionVocabularyUsesNothingElseOfTheApp(): void {
		$this->assertSame([], self::dependencies()['Definition'] ?? []);
	}

	public function testGenericCodeNamesNoCheck(): void {
		$naming = [];
		foreach (self::files() as $file => $unit) {
			if (in_array($unit, self::PLATFORM, true)) {
				foreach (self::references($file) as $class) {
					if (str_starts_with($class, self::APP . 'Check\\Checks\\')) {
						$naming[$file] = self::NAMES_A_CHECK[$file] ?? 'not listed';
						break;
					}
				}
			}
		}
		ksort($naming);
		$expected = self::NAMES_A_CHECK;
		ksort($expected);
		$this->assertSame($expected, $naming, 'generic code reads per-check rules from the CheckDefinition');
	}

	/**
	 * @return array<string, array<string, list<string>>>
	 */
	private static function dependencies(): array {
		if (self::$dependencies === null) {
			self::$dependencies = [];
			foreach (self::files() as $file => $unit) {
				self::$dependencies[$unit] ??= [];
				foreach (self::references($file) as $class) {
					$to = self::unitOf($class);
					if ($to !== $unit) {
						self::$dependencies[$unit][$to][] = $file;
					}
				}
			}
			foreach (self::$dependencies as &$tos) {
				ksort($tos);
				$tos = array_map(static fn (array $files): array => array_values(array_unique($files)), $tos);
			}
			unset($tos);
			ksort(self::$dependencies);
		}
		return self::$dependencies;
	}

	/**
	 * @return array<string, string> path below lib/ => unit
	 */
	private static function files(): array {
		$files = [];
		$lib = realpath(self::LIB);
		if ($lib === false) {
			throw new \LogicException('lib/ not found');
		}
		foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($lib, \FilesystemIterator::SKIP_DOTS)) as $file) {
			if ($file instanceof \SplFileInfo && $file->getExtension() === 'php') {
				$path = substr($file->getPathname(), strlen($lib) + 1);
				$files[$path] = self::unitOf(self::APP . str_replace('/', '\\', substr($path, 0, -4)));
			}
		}
		ksort($files);
		return $files;
	}

	private static function unitOf(string $class): string {
		$parts = explode('\\', substr($class, strlen(self::APP)));
		if ($parts[0] === 'Check' && count($parts) > 2 && $parts[1] === 'Checks') {
			return 'Check\\' . $parts[1];
		}
		return $parts[0];
	}

	private static function layer(string $unit): int {
		foreach (array_values(self::LAYERS) as $index => $units) {
			if (in_array($unit, $units, true)) {
				return $index;
			}
		}
		throw new \LogicException($unit . ' has no layer');
	}

	/**
	 * The app classes a file names in code. The app id constant of
	 * Application is no dependency on the bootstrap: every layer needs it.
	 *
	 * @return list<string>
	 */
	private static function references(string $file): array {
		$code = (string)file_get_contents(self::LIB . '/' . $file);
		$tokens = token_get_all($code);
		$namespace = '';
		$imports = [];
		$names = [];
		$depth = 0;
		$members = [];
		$count = count($tokens);
		for ($i = 0; $i < $count; $i++) {
			$token = $tokens[$i];
			if (!is_array($token)) {
				$depth += $token === '{' ? 1 : ($token === '}' ? -1 : 0);
				continue;
			}
			[$id, $text] = $token;
			if ($id === T_CURLY_OPEN || $id === T_DOLLAR_OPEN_CURLY_BRACES) {
				$depth++;
			} elseif ($id === T_NAMESPACE) {
				$namespace = self::nextName($tokens, $i);
			} elseif ($id === T_USE && $depth === 0) {
				$name = self::nextName($tokens, $i);
				$alias = substr($name, (int)strrpos('\\' . $name, '\\'));
				for ($j = $i + 1; $j < $count && $tokens[$j] !== ';'; $j++) {
					if (is_array($tokens[$j]) && $tokens[$j][0] === T_AS) {
						$alias = self::nextName($tokens, $j);
					}
				}
				$imports[$alias] = $name;
				$names[] = $name;
				$i = $j;
			} elseif ($id === T_NAME_FULLY_QUALIFIED) {
				$names[] = ltrim($text, '\\');
			} elseif ($id === T_NAME_QUALIFIED) {
				[$first, $rest] = explode('\\', $text, 2);
				$names[] = isset($imports[$first]) ? $imports[$first] . '\\' . $rest : $namespace . '\\' . $text;
			} elseif ($id === T_DOUBLE_COLON && is_array($tokens[$i - 1]) && $tokens[$i - 1][1] === 'Application') {
				$members[] = is_array($tokens[$i + 1]) ? $tokens[$i + 1][1] : '';
			} elseif ($id === T_NEW && is_array($tokens[$i + 2] ?? null) && $tokens[$i + 2][1] === 'Application') {
				$members[] = 'new';
			}
		}
		$appIdOnly = $members !== [] && array_unique($members) === ['APP_ID'];
		return array_values(array_unique(array_filter($names, static fn (string $name): bool => str_starts_with($name, self::APP)
			&& !($appIdOnly && $name === self::APP . 'AppInfo\\Application'))));
	}

	/**
	 * The name after the token at $i, skipping whitespace; $i moves to it.
	 *
	 * @param list<mixed> $tokens
	 */
	private static function nextName(array $tokens, int &$i): string {
		for ($j = $i + 1; isset($tokens[$j]); $j++) {
			if (is_array($tokens[$j]) && in_array($tokens[$j][0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_STRING], true)) {
				$i = $j;
				return ltrim($tokens[$j][1], '\\');
			}
			if (!is_array($tokens[$j]) || $tokens[$j][0] !== T_WHITESPACE) {
				return '';
			}
		}
		return '';
	}
}
