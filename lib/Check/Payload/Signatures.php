<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCP\IL10N;

/**
 * The built-in signatures of the injection probe check.
 *
 * Every pattern runs on a value after {@see Normalizer}: lower-cased, URL-decoded,
 * comments removed and whitespace collapsed to single spaces. Patterns are bounded
 * and have no nested quantifiers, so matching stays linear in the length of the
 * value; a test runs each against long adversarial input.
 *
 * Ids are stable: admins refer to them when they turn a signature off. Change
 * VERSION whenever the list changes.
 */
final class Signatures {
	public const VERSION = 1;

	/** Not a letter, digit or underscore before the match */
	private const B = '(?<![a-z0-9_])';
	/** Not a letter, digit or underscore after the match */
	private const E = '(?![a-z0-9_])';

	/**
	 * SQL injection signatures: id => [pattern, weight, counts only with another match].
	 * They run on plain values and on decoded base64.
	 *
	 * @var array<string, array{0: string, 1: int, 2?: bool}>
	 */
	private const SQL = [
		'sql_union_select' => ['~(?<![a-z_])union ?(?:(?:all|distinct) ?)?\(? ?select' . self::E . '~', 3],
		'sql_tautology' => ['~[\'"`] ?(?:or|and|xor|\|\||&&) ?[\'"`(]?[a-z0-9_]{1,32}[\'"`)]? ?(?:<=>|<>|!=|=|<|>|like ) ?[\'"`(]?[a-z0-9_]{1,32}~', 3],
		'sql_numeric_tautology' => ['~' . self::B . '(?:or|and|xor) (\d{1,10}) ?= ?\1(?![0-9])~', 2],
		'sql_sleep' => ['~' . self::B . '(?:pg_)?sleep ?\( ?\d{1,9}(?:\.\d{1,6})? ?\)~', 3],
		'sql_benchmark' => ['~' . self::B . 'benchmark ?\( ?\d~', 3],
		'sql_waitfor' => ['~' . self::B . 'waitfor (?:delay|time) ?[\'"]~', 3],
		'sql_schema' => ['~' . self::B . '(?:information_schema|pg_catalog|pg_shadow|sqlite_master|sqlite_schema|mysql\.user|sysobjects|sys\.objects)' . self::E . '~', 3],
		'sql_error_function' => ['~' . self::B . '(?:extractvalue|updatexml|load_file|utl_inaddr\.get_host_name|ctxsys\.drithsx\.sn) ?\(~', 3],
		'sql_file_write' => ['~' . self::B . 'into (?:out|dump)file' . self::E . '~', 3],
		'sql_mssql_procedure' => ['~' . self::B . '(?:xp_cmdshell|sp_executesql|sp_oacreate|sp_configure)' . self::E . '~', 3],
		'sql_stacked_query' => ['~; ?(?:drop|delete|insert|update|create|alter|truncate|exec|execute|declare|shutdown|select)' . self::E . '~', 2],
		'sql_subquery' => ['~(?:' . self::B . '(?:and|or|union)|[=(,]) ?\( ?select' . self::E . '~', 2],
		'sql_order_probe' => ['~[\'"] ?(?:order|group) by \d{1,4}(?![0-9])~', 2],
		'sql_quote_terminator' => ['~[\'"`)] ?(?:--|#|;|/\*)~', 1],
		'sql_trailing_comment' => ['~(?:--|#) ?$~D', 1],
		'sql_select_from' => ['~' . self::B . 'select' . self::E . '.{1,200}?' . self::B . 'from' . self::E . '~', 1],
		'sql_server_variable' => ['~@@(?:version|datadir|hostname|basedir)' . self::E . '~', 1],
		'sql_hex_literal' => ['~' . self::B . '0x[0-9a-f]{8}~', 1, true],
	];

	/**
	 * Payload signatures, weight 3 each: id => [pattern, scope].
	 * Encoded-only ones are too common in harmless plain text (a link, "../..")
	 * but have no business inside a base64 value.
	 *
	 * @var array<string, array{0: string, 1: Signature::SCOPE_*}>
	 */
	private const PAYLOAD = [
		'payload_php_tag' => ['~<\?php' . self::E . '~', Signature::SCOPE_ANY],
		'payload_script_tag' => ['~<script(?![a-z0-9_-])~', Signature::SCOPE_ANY],
		'payload_log4shell' => ['~\$\{ ?(?:jndi ?:|\$\{|(?:lower|upper|env|sys|date|main|base64) ?:|::-)~', Signature::SCOPE_ANY],
		'payload_system_file' => ['~/etc/(?:passwd|shadow)' . self::E . '~', Signature::SCOPE_ANY],
		'payload_javascript_uri' => ['~javascript ?:~', Signature::SCOPE_ENCODED],
		'payload_event_handler' => ['~' . self::B . 'on(?:error|load) ?=~', Signature::SCOPE_ENCODED],
		'payload_path_traversal' => ['~\.\.[/\\\\]\.\.[/\\\\]~', Signature::SCOPE_ENCODED],
		'payload_shell_download' => ['~' . self::B . '(?:wget|curl) (?:-[a-z0-9-]{1,20} )?https?://[^ |]{1,300}+(?: [^|]{0,100}+)?\| ?(?:sh|bash)' . self::E . '~', Signature::SCOPE_ENCODED],
		'payload_shell_exec' => ['~[;|&`] ?(?:sh|bash|zsh|dash) -[ci]' . self::E . '~', Signature::SCOPE_ENCODED],
		'payload_netcat' => ['~' . self::B . '(?:nc|ncat|netcat) -[a-z]{0,4}e' . self::E . '~', Signature::SCOPE_ENCODED],
		'payload_php_eval' => ['~(?<![a-z0-9_$])(?:eval|assert) ?\(~', Signature::SCOPE_ENCODED],
		'payload_php_exec' => ['~(?<![a-z0-9_$>:])(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec) ?\(~', Signature::SCOPE_ENCODED],
		'payload_php_decode' => ['~' . self::B . '(?:base64_decode|gzinflate|str_rot13) ?\(~', Signature::SCOPE_ENCODED],
	];

	public const PAYLOAD_WEIGHT = 3;

	/**
	 * @return list<Signature>
	 */
	public static function builtIn(): array {
		$list = [];
		foreach (self::SQL as $id => $definition) {
			$list[] = new Signature($id, $definition[0], $definition[1], Signature::SCOPE_ANY, $definition[2] ?? false);
		}
		foreach (self::PAYLOAD as $id => [$pattern, $scope]) {
			$list[] = new Signature($id, $pattern, self::PAYLOAD_WEIGHT, $scope);
		}
		return $list;
	}

	/**
	 * @return list<string>
	 */
	public static function ids(): array {
		return array_merge(array_keys(self::SQL), array_keys(self::PAYLOAD));
	}

	/**
	 * A short explanation of a signature for the admin page.
	 */
	public static function describe(string $id, IL10N $l): string {
		return match ($id) {
			'sql_union_select' => $l->t('UNION SELECT, which adds the attacker\'s own query to the real one'),
			'sql_tautology' => $l->t('A quote followed by a comparison that is always true, like \' OR \'1\'=\'1'),
			'sql_numeric_tautology' => $l->t('A comparison that is always true, without quotes, like OR 1=1'),
			'sql_sleep' => $l->t('SLEEP() or PG_SLEEP(), which make the database wait, to find a weakness by timing'),
			'sql_benchmark' => $l->t('BENCHMARK(), which keeps the database busy, to find a weakness by timing'),
			'sql_waitfor' => $l->t('WAITFOR DELAY, which makes a Microsoft SQL Server database wait'),
			'sql_schema' => $l->t('Names of database system tables, like information_schema'),
			'sql_error_function' => $l->t('Functions that leak data through error messages, like EXTRACTVALUE()'),
			'sql_file_write' => $l->t('INTO OUTFILE, which writes query results to a file on the database server'),
			'sql_mssql_procedure' => $l->t('Dangerous Microsoft SQL Server procedures, like xp_cmdshell'),
			'sql_stacked_query' => $l->t('A semicolon followed by a second command, like ; DROP'),
			'sql_subquery' => $l->t('A nested SELECT after AND, OR or a comparison'),
			'sql_order_probe' => $l->t('A quote followed by ORDER BY and a number, used to count the columns of a table'),
			'sql_quote_terminator' => $l->t('A quote that ends a text, followed by a comment or a semicolon'),
			'sql_trailing_comment' => $l->t('A comment at the end of the value, which cuts off the rest of a query'),
			'sql_select_from' => $l->t('SELECT … FROM'),
			'sql_server_variable' => $l->t('Database server variables, like @@version'),
			'sql_hex_literal' => $l->t('A long hexadecimal number (0x…), counted only together with another signature'),
			'payload_php_tag' => $l->t('The start of PHP code (<?php)'),
			'payload_script_tag' => $l->t('An HTML script tag'),
			'payload_log4shell' => $l->t('A Log4Shell lookup, like ${jndi:'),
			'payload_system_file' => $l->t('The system password files /etc/passwd or /etc/shadow'),
			'payload_javascript_uri' => $l->t('A javascript: link'),
			'payload_event_handler' => $l->t('An HTML event handler, like onerror='),
			'payload_path_traversal' => $l->t('Climbing up folders with ../../'),
			'payload_shell_download' => $l->t('Downloading a script and running it in a shell, like wget … | sh'),
			'payload_shell_exec' => $l->t('Starting a shell with a command, like ; sh -c'),
			'payload_netcat' => $l->t('Netcat with -e, which opens a remote shell'),
			'payload_php_eval' => $l->t('The PHP functions eval() or assert(), which run code'),
			'payload_php_exec' => $l->t('PHP functions that run system commands, like system()'),
			'payload_php_decode' => $l->t('PHP functions that unpack hidden code, like base64_decode()'),
			default => $l->t('Custom signature'),
		};
	}

	/**
	 * Every built-in signature for the admin page and the "Test a URL" tool.
	 *
	 * @return list<array{id: string, weight: int, scope: string, requiresOther: bool, description: string}>
	 */
	public static function catalog(IL10N $l): array {
		return array_map(static fn (Signature $s): array => [
			'id' => $s->id,
			'weight' => $s->weight,
			'scope' => $s->scope,
			'requiresOther' => $s->requiresOther,
			'description' => self::describe($s->id, $l),
		], self::builtIn());
	}
}
