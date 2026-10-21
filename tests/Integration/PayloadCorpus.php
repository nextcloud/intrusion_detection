<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

/**
 * The fixed corpus of the injection probe check (section 20 of the concept).
 * It must stay green whenever the signatures change.
 *
 * Requests are written as a client sends them: the URI percent-encoded where
 * a browser or scanner would encode, the form fields as PHP parsed them.
 */
final class PayloadCorpus {
	/**
	 * Must fire, not logged in.
	 *
	 * @return array<string, array{0: string, 1: string, 2: array<string, string>}> name => [uri, script name, form fields]
	 */
	public static function mustFire(): array {
		$doubleBase64 = base64_encode(base64_encode("' OR '1'='1"));
		$cases = [
			'classic tautology' => ['/index.php/apps/foo?id=1\'%20OR%20\'1\'=\'1', 'id'],
			'URL-encoded' => ['/index.php/apps/foo?id=1%27%20OR%201%3D1--', 'id'],
			'double-encoded' => ['/index.php/apps/foo?id=1%2527%2520OR%25201%253D1', 'id'],
			'union' => ['/index.php/apps/foo?cat=1%20UNION%20ALL%20SELECT%20username,password%20FROM%20oc_users', 'cat'],
			'comment evasion' => ['/index.php/apps/foo?cat=1/**/UNION/**/SELECT/**/1,2,3', 'cat'],
			'MSSQL time-based' => ['/index.php/apps/foo?q=1;WAITFOR%20DELAY%20\'0:0:5\'--', 'q'],
			'time-based SLEEP' => ['/index.php/apps/foo?id=1%20AND%20SLEEP(5)', 'id'],
			'time-based pg_sleep' => ['/index.php/apps/foo?id=1%20AND%20pg_sleep(5)', 'id'],
			'error-based' => ['/index.php/apps/foo?id=1%20AND%20extractvalue(1,concat(0x7e,version()))', 'id'],
			'schema probing' => ['/index.php/apps/foo?x=1%20AND%201=1%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables', 'x'],
			'base64 SQL' => ['/index.php/apps/foo?data=JyBPUiAnMSc9JzE=', 'data'],
			'base64url SQL, unpadded' => ['/index.php/apps/foo?d=VU5JT04gU0VMRUNUIHBhc3N3b3JkIEZST00gb2NfdXNlcnM', 'd'],
			'base64 PHP' => ['/index.php/apps/foo?p=PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==', 'p'],
			'base64 Log4Shell' => ['/index.php/apps/foo?x=JHtqbmRpOmxkYXA6Ly9ldmlsLmV4YW1wbGUvYX0=', 'x'],
			'base64 shell dropper' => ['/index.php/apps/foo?c=d2dldCBodHRwOi8vZXZpbC5leGFtcGxlL3ggfCBzaA==', 'c'],
			'double base64' => ['/index.php/apps/foo?z=' . $doubleBase64, 'z'],
		];
		$corpus = [];
		foreach ($cases as $name => [$uri, $param]) {
			$corpus[$name . ', query string'] = [$uri, '/index.php', []];
			// The same value as a form field, as PHP parses it: URL-decoded once.
			parse_str((string)parse_url($uri, PHP_URL_QUERY), $fields);
			$corpus[$name . ', form field'] = ['/index.php/apps/foo', '/index.php', [$param => (string)$fields[$param]]];
		}
		$corpus['SQL in the path'] = ['/index.php/apps/foo/1\'%20OR%20\'1\'=\'1', '/index.php', []];
		$corpus['form fields together'] = ['/index.php/login', '/index.php', ['user' => 'admin\'--', 'x' => '1 UNION SELECT 1']];
		return $corpus;
	}

	/**
	 * Must not fire, not logged in.
	 *
	 * @return array<string, array{0: string, 1: string, 2: array<string, string>}>
	 */
	public static function mustNotFire(): array {
		// 64 fixed bytes that are not text, base64-encoded like an encrypted state.
		$state = rawurlencode(base64_encode(hash('sha512', 'injection probe corpus', true)));
		return [
			'file names are excluded' => ['/remote.php/dav/files/alice/Bob\'s%20union%20select%20notes.txt', '/remote.php', []],
			'file names in public WebDAV are excluded' => ['/public.php/dav/files/AbCdEfGhIjKlMnO/Bob\'s%20union%20select%20notes.txt', '/public.php', []],
			'free-text parameter on unified search' => ['/ocs/v2.php/search/providers/files/search?term=select%20from%20where', '/ocs/v2.php', []],
			'password field' => ['/index.php/apps/foo?password=JyBPUiAnMSc9JzE=', '/index.php', []],
			'request token' => ['/index.php/apps/foo?requesttoken=JyBPUiAnMSc9JzE%3D%3AJyBPUiAnMSc9JzE%3D', '/index.php', []],
			'password form field' => ['/index.php/login', '/index.php', ['user' => 'alice', 'password' => "' OR '1'='1' UNION SELECT 1 --", 'requesttoken' => 'JyBPUiAnMSc9JzE=']],
			'preview' => ['/index.php/core/preview?fileId=12345&x=32&y=32&a=1', '/index.php', []],
			'random state' => ['/index.php/apps/oauth2/authorize?state=' . $state, '/index.php', []],
			'redirect URL' => ['/index.php/login?redirect_url=%2Fapps%2Ffiles%2F', '/index.php', []],
			'one quote' => ['/index.php/apps/foo?name=O\'Brien', '/index.php', []],
			'quotes without SQL' => ['/index.php/apps/foo?q=it\'s%205%20o\'clock', '/index.php', []],
			'harmless base64' => ['/index.php/apps/foo?search=dGVzdA==', '/index.php', []],
		];
	}

	/**
	 * Values the matcher itself must not weigh as a hit, even when their
	 * parameter is not excluded.
	 *
	 * @return array<string, array{string}>
	 */
	public static function harmlessValues(): array {
		return [
			'one quote' => ['O\'Brien'],
			'quotes without SQL' => ['it\'s 5 o\'clock'],
			'select from where as words' => ['select from where'],
			'harmless base64' => ['dGVzdA=='],
			'a sentence with or and equals' => ['black or white = grey?'],
			'a path' => ['/apps/files/?dir=/Documents&openfile=true'],
			'an email address' => ['o\'brien@example.com'],
			'a date range' => ['2026-01-01--2026-12-31'],
			'an app id' => ['integration_openai'],
			'a UUID' => ['3F2504E0-4F89-11D3-9A0C-0305E82C3301'],
		];
	}
}
