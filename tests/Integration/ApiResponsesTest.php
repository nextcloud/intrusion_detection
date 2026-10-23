<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Tests\Unit\Controller\RouteTable;
use OCP\AppFramework\OCSController;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The status and body of the API's answers as a client receives them, by
 * route: the errors of every admin controller, and the success of the
 * writes whose code moves.
 */
#[Group('DB')]
class ApiResponsesTest extends IntegrationTestCase {
	use OcsPipeline;

	private const ADMIN = 'ids_pin_admin';

	/** Status and top-level keys of the reads, by route */
	private const READS = [
		'GET /api/v1/status' => [200, ['state', 'learning', 'checks', 'last24h', 'activeBans', 'prerequisites', 'cost', 'costSampleRate', 'problems', 'extensions']],
		'GET /api/v1/checks' => [200, ['checks', 'categories', 'modes', 'severities']],
		'GET /api/v1/protection-level' => [200, ['level']],
		'GET /api/v1/detections' => [200, ['detections', 'hasMore']],
		'GET /api/v1/stats/daily' => [200, ['days', 'timezone']],
		'GET /api/v1/bans' => [200, ['bans', 'hasMore', 'activeCount', 'limits']],
		'GET /api/v1/lookup' => [200, ['kind', 'query', 'bans', 'detections', 'user']],
		'GET /api/v1/learning' => [200, ['active', 'until', 'daysLeft', 'minDays', 'maxDays']],
		'GET /api/v1/settings' => [200, ['settings', 'templates']],
		'GET /api/v1/settings/export' => [200, ['format', 'version', 'exportedAt', 'settings', 'checks']],
		'GET /api/v1/approvals' => [200, []],
		'GET /api/v1/approvals/admin-grants' => [200, []],
		'GET /api/v1/blocklists' => [200, ['lists', 'countsMatches', 'matchDays', 'check', 'networkCheck', 'maxLists', 'minInterval', 'maxInterval', 'formats']],
		'GET /api/v1/export' => [200, ['directory', 'active', 'formats', 'files', 'lastWriteAt', 'error', 'errorText', 'errorAt', 'entries', 'configKey', 'snippetsUseDirectory', 'exampleDirectory', 'snippets']],
		'GET /api/v1/confirmation' => [200, ['methods', 'policies', 'preset', 'outcomes', 'users', 'admins', 'approvers', 'approvals']],
		'GET /api/v1/confirmation/waiting' => [200, []],
		'GET /api/v1/confirmation/accounts' => [200, []],
		'GET /api/v1/decoys' => [200, ['decoys', 'decoyCheck', 'reservedCheck', 'trapCheck', 'decoyCollisions', 'reservedNames', 'trapPaths', 'limits']],
		'GET /api/v1/digest' => [200, ['frequency', 'timezone', 'nextDue', 'last', 'recipients', 'withoutEmail', 'withoutEmailCount', 'mailConfigured', 'viewerHasEmail']],
		'GET /api/v1/events' => [200, ['includeIp', 'webhooksEnabled', 'events']],
		'GET /api/v1/notifications' => [200, ['recipients', 'recipientLimit', 'mail', 'me', 'checks']],
		'GET /api/v1/payload/signatures' => [200, ['version', 'minWeight', 'signatures', 'custom', 'maxCustom', 'maxLength', 'defaultWeight']],
		'GET /api/v1/privacy' => [200, ['stored', 'outgoing', 'gdpr']],
	];

	protected function setUp(): void {
		parent::setUp();
		$userManager = Server::get(IUserManager::class);
		if (!$userManager->userExists(self::ADMIN)) {
			$userManager->createUser(self::ADMIN, 'Ids-Test-Password-2026');
		}
		Server::get(IUserSession::class)->setUser($userManager->get(self::ADMIN));
	}

	protected function tearDown(): void {
		Server::get(IUserSession::class)->setUser(null);
		Server::get(IUserManager::class)->get(self::ADMIN)?->delete();
		parent::tearDown();
	}

	/**
	 * @return array<string, array{0: string, 1: array<string, mixed>, 2: array{status: int, message: ?string, data: mixed}}>
	 */
	public static function errors(): array {
		return [
			'unknown check' => [
				'PUT /api/v1/checks/{id}',
				['id' => 'no_such_check', 'mode' => 'off'],
				['status' => 404, 'message' => '', 'data' => ['message' => 'There is no check "no_such_check".', 'param' => null, 'reason' => 'not_found']],
			],
			'unknown mode' => [
				'PUT /api/v1/checks/{id}',
				['id' => 'password_spraying', 'mode' => 'everything'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The mode must be off, observe or protect.', 'param' => null, 'reason' => 'unknown_mode']],
			],
			'param too small' => [
				'PUT /api/v1/checks/{id}',
				['id' => 'password_spraying', 'params' => ['min_names' => 1]],
				['status' => 400, 'message' => '', 'data' => ['message' => '"min_names" must be at least 3.', 'param' => 'min_names', 'reason' => 'too_small']],
			],
			'unknown response' => [
				'PUT /api/v1/checks/{id}',
				['id' => 'password_spraying', 'responses' => ['kill_everything']],
				['status' => 400, 'message' => '', 'data' => ['message' => '"kill_everything" is not a response this check can use.', 'param' => null, 'reason' => 'unknown_response']],
			],
			'unknown param' => [
				'PUT /api/v1/checks/{id}',
				['id' => 'password_spraying', 'params' => ['nope' => 1]],
				['status' => 400, 'message' => '', 'data' => ['message' => 'This check has no setting "nope".', 'param' => 'nope', 'reason' => 'unknown_param']],
			],
			'reset unknown check' => [
				'POST /api/v1/checks/{id}/reset',
				['id' => 'no_such_check'],
				['status' => 404, 'message' => '', 'data' => ['message' => 'There is no check "no_such_check".', 'param' => null, 'reason' => 'not_found']],
			],
			'custom level' => [
				'PUT /api/v1/protection-level',
				['level' => 'custom'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose the recommended, strict or relaxed protection level.', 'param' => 'level', 'reason' => 'invalid_level']],
			],
			'bad severity filter' => [
				'GET /api/v1/detections',
				['severity' => 'huge'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The filter "severity" is not valid.', 'param' => 'severity', 'reason' => 'invalid_filter']],
			],
			'bad address filter' => [
				'GET /api/v1/detections',
				['address' => 'nope'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The filter "address" is not valid.', 'param' => 'address', 'reason' => 'invalid_filter']],
			],
			'bad limit' => [
				'GET /api/v1/detections',
				['limit' => 101],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The filter "limit" is not valid.', 'param' => 'limit', 'reason' => 'invalid_filter']],
			],
			'missing detection' => [
				'GET /api/v1/detections/{id}',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This detection does not exist (any more).', 'param' => null, 'reason' => 'not_found']],
			],
			'ban level' => [
				'POST /api/v1/bans',
				['target' => '203.0.113.7', 'level' => 4],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The level must be 1, 2 or 3.', 'param' => 'level', 'reason' => 'invalid_level']],
			],
			'ban duration' => [
				'POST /api/v1/bans',
				['target' => '203.0.113.7', 'duration' => 60],
				['status' => 400, 'message' => '', 'data' => ['message' => 'A block lasts from 5 minutes to 90 days.', 'param' => 'duration', 'reason' => 'invalid_duration']],
			],
			'ban note' => [
				'POST /api/v1/bans',
				['target' => '203.0.113.7', 'note' => str_repeat('x', 256)],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The note can have at most 255 characters.', 'param' => 'note', 'reason' => 'too_long']],
			],
			'ban target' => [
				'POST /api/v1/bans',
				['target' => 'example.com'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.', 'param' => 'target', 'reason' => 'invalid_target']],
			],
			'ban prefix' => [
				'POST /api/v1/bans',
				['target' => '203.0.113.0/abc'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.', 'param' => 'target', 'reason' => 'invalid_target']],
			],
			'ban loopback' => [
				'POST /api/v1/bans',
				['target' => '127.0.0.1'],
				['status' => 400, 'message' => '', 'data' => ['message' => '127.0.0.1 is this server or a loopback address. It is never blocked.', 'param' => 'target', 'reason' => 'invalid_target']],
			],
			'ban ipv4 /16' => [
				'POST /api/v1/bans',
				['target' => '203.0.0.0/16'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.', 'param' => 'target', 'reason' => 'invalid_target']],
			],
			'lift without note' => [
				'DELETE /api/v1/bans/{id}',
				['id' => 1, 'note' => ' '],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Please say why the block is lifted. The note is kept with the block and in the audit log.', 'param' => 'note', 'reason' => 'required']],
			],
			'lift long note' => [
				'DELETE /api/v1/bans/{id}',
				['id' => 1, 'note' => str_repeat('x', 256)],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The note can have at most 255 characters.', 'param' => 'note', 'reason' => 'too_long']],
			],
			'lift missing ban' => [
				'DELETE /api/v1/bans/{id}',
				['id' => 999999, 'note' => 'gone'],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This block does not exist (any more).', 'param' => null, 'reason' => 'not_found']],
			],
			'learning action' => [
				'PUT /api/v1/learning',
				['action' => 'forever'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose to start, extend or stop learning mode.', 'param' => 'action', 'reason' => 'invalid_action']],
			],
			'learning days' => [
				'PUT /api/v1/learning',
				['action' => 'start', 'days' => 31],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Learning mode lasts 1 to 30 days.', 'param' => 'days', 'reason' => 'invalid_days']],
			],
			'unknown setting' => [
				'PUT /api/v1/settings',
				['values' => ['no_such_setting' => 1]],
				['status' => 400, 'message' => '', 'data' => ['message' => 'This check has no setting "no_such_setting".', 'param' => 'no_such_setting', 'reason' => 'unknown_param']],
			],
			'internal setting' => [
				'PUT /api/v1/settings',
				['values' => ['learning_until' => 1]],
				['status' => 400, 'message' => '', 'data' => ['message' => 'This check has no setting "learning_until".', 'param' => 'learning_until', 'reason' => 'unknown_param']],
			],
			'bad setting value' => [
				'PUT /api/v1/settings',
				['values' => ['ban_net_after' => 'many']],
				['status' => 400, 'message' => '', 'data' => ['message' => '"ban_net_after" must be a whole number.', 'param' => 'ban_net_after', 'reason' => 'not_an_integer']],
			],
			'approve missing' => [
				'POST /api/v1/approvals/{id}/approve',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'There is no such request.', 'param' => null, 'reason' => 'not_found']],
			],
			'reject missing' => [
				'POST /api/v1/approvals/{id}/reject',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'There is no such request.', 'param' => null, 'reason' => 'not_found']],
			],
			'blocklist exists' => [
				'POST /api/v1/blocklists',
				['id' => 'spamhaus_drop_v4', 'url' => 'https://example.org/x', 'purpose' => 'deny'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'A list with this name exists already.', 'param' => 'id', 'reason' => 'list_exists']],
			],
			'blocklist bad url' => [
				'POST /api/v1/blocklists',
				['id' => 'my_list', 'url' => 'http://example.org/x', 'purpose' => 'deny'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Lists can only be downloaded from https:// addresses outside the local network, without a user name or password in the address.', 'param' => 'url', 'reason' => 'url_refused']],
			],
			'blocklist bad id' => [
				'POST /api/v1/blocklists',
				['id' => 'My List', 'url' => 'https://example.org/x', 'purpose' => 'deny'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'A list name must start with a letter and use only lower-case letters, digits and underscores, at most 32 characters.', 'param' => 'id', 'reason' => 'invalid_list_id']],
			],
			'blocklist missing' => [
				'PUT /api/v1/blocklists/{id}',
				['id' => 'no_such_list', 'enabled' => true],
				['status' => 404, 'message' => '', 'data' => ['message' => 'There is no list "no_such_list".', 'param' => null, 'reason' => 'not_found']],
			],
			'blocklist bad mode' => [
				'PUT /api/v1/blocklists/{id}',
				['id' => 'spamhaus_drop_v4', 'mode' => 'maybe'],
				['status' => 400, 'message' => '', 'data' => ['message' => '"mode" must be one of: observe, protect.', 'param' => 'mode', 'reason' => 'not_a_choice']],
			],
			'remove builtin list' => [
				'DELETE /api/v1/blocklists/{id}',
				['id' => 'spamhaus_drop_v4'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The address, purpose and format of a built-in list cannot be changed, and it cannot be removed. Switch it off instead.', 'param' => null, 'reason' => 'builtin_list']],
			],
			'decoy format' => [
				'POST /api/v1/decoys',
				['label' => 'x', 'secretFormat' => 'pem'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose what the secret looks like: an app password or a token.', 'param' => 'secretFormat', 'reason' => 'invalid_format']],
			],
			'decoy label' => [
				'POST /api/v1/decoys',
				['label' => ''],
				['status' => 400, 'message' => '', 'data' => ['message' => '"label" contains an invalid entry: ', 'param' => 'label', 'reason' => 'invalid_item']],
			],
			'decoy missing' => [
				'DELETE /api/v1/decoys/{id}',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This decoy does not exist (any more).', 'param' => null, 'reason' => 'not_found']],
			],
			'reserved name invalid' => [
				'PUT /api/v1/reserved-names',
				['add' => ['has space']],
				['status' => 400, 'message' => '', 'data' => ['message' => '"names" contains an invalid entry: has space', 'param' => 'names', 'reason' => 'invalid_item']],
			],
			'reserved name existing' => [
				'PUT /api/v1/reserved-names',
				['add' => [self::ADMIN]],
				['status' => 400, 'message' => '', 'data' => ['message' => '"ids_pin_admin" is an existing account. Only names that no account uses can be reserved or used as decoys.', 'param' => 'names', 'reason' => 'existing_user']],
			],
			'trap path nextcloud' => [
				'PUT /api/v1/trap-paths',
				['add' => ['/index.php']],
				['status' => 400, 'message' => '', 'data' => ['message' => '"/index.php" is, or covers, a path Nextcloud itself uses, so legitimate clients would be blocked.', 'param' => 'paths', 'reason' => 'nextcloud_path']],
			],
			'trap path too many' => [
				'PUT /api/v1/trap-paths',
				['add' => array_map(static fn (int $i): string => '/t' . $i, range(1, 101))],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Change at most 100 paths at once.', 'param' => 'paths', 'reason' => 'too_many_items']],
			],
			'preset unknown' => [
				'PUT /api/v1/confirmation/preset',
				['preset' => 'maybe'],
				['status' => 400, 'message' => '', 'data' => ['message' => '"preset" must be one of: recommended, refuse, allow.', 'param' => 'preset', 'reason' => 'not_a_choice']],
			],
			'report subject' => [
				'POST /api/v1/incidents/report',
				[],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose either an account or an address.', 'param' => 'subject', 'reason' => 'subject']],
			],
			'report address' => [
				'POST /api/v1/incidents/report',
				['address' => 'nope'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Enter a single IPv4 or IPv6 address, for example 203.0.113.7.', 'param' => 'address', 'reason' => 'invalid_address']],
			],
			'report range' => [
				'POST /api/v1/incidents/report',
				['user' => self::ADMIN, 'since' => 2000, 'until' => 1000],
				['status' => 400, 'message' => '', 'data' => ['message' => 'The start of the period must be before its end.', 'param' => 'since', 'reason' => 'range_order']],
			],
			'download output' => [
				'POST /api/v1/incidents/report/download',
				['output' => 'pdf', 'user' => self::ADMIN],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose JSON or HTML.', 'param' => 'output', 'reason' => 'invalid_output']],
			],
			'download subject' => [
				'POST /api/v1/incidents/report/download',
				['output' => 'json'],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Choose either an account or an address.', 'param' => 'subject', 'reason' => 'subject']],
			],
			'secure account missing' => [
				'GET /api/v1/detections/{id}/secure-account',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This detection does not exist (any more).', 'param' => null, 'reason' => 'not_found']],
			],
			'reenable missing' => [
				'POST /api/v1/detections/{id}/reenable',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This detection does not exist (any more).', 'param' => null, 'reason' => 'not_found']],
			],
			'simulation missing' => [
				'GET /api/v1/checks/{id}/simulation',
				['id' => 'no_such_check'],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This check cannot be simulated.', 'param' => null, 'reason' => 'not_found']],
			],
			'signatures too many' => [
				'POST /api/v1/payload/signatures/check',
				['entries' => array_map(static fn (int $i): string => 'sig' . $i, range(1, 1000))],
				['status' => 400, 'message' => '', 'data' => ['message' => 'There can be at most 50 custom signatures.', 'param' => 'entries', 'reason' => 'too_many_items']],
			],
			'payload empty' => [
				'POST /api/v1/payload/test',
				['input' => ' '],
				['status' => 400, 'message' => '', 'data' => ['message' => 'Paste a web address or a value to test.', 'param' => 'input', 'reason' => 'empty']],
			],
			'digest test no address' => [
				'POST /api/v1/digest/test',
				[],
				['status' => 400, 'message' => '', 'data' => ['message' => 'You have no email address, so the test digest cannot be sent. Add one in your personal settings.', 'param' => null, 'reason' => 'no_address']],
			],
			'personal deny missing' => [
				'POST /api/v1/personal/detections/{id}/deny',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This event does not exist, or it is not about your account.', 'param' => null, 'reason' => 'not_found']],
			],
			'personal confirm missing' => [
				'POST /api/v1/personal/detections/{id}/confirm',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This event does not exist, or it is not about your account.', 'param' => null, 'reason' => 'not_found']],
			],
			'stale credential missing' => [
				'DELETE /api/v1/personal/stale-credentials/{id}',
				['id' => 999999],
				['status' => 404, 'message' => '', 'data' => ['message' => 'This is not one of your unused app passwords or devices.', 'param' => null, 'reason' => 'not_found']],
			],
		];
	}

	/**
	 * @param array<string, mixed> $arguments
	 * @param array{status: int, message: ?string, data: mixed} $expected
	 */
	#[DataProvider('errors')]
	public function testErrors(string $route, array $arguments, array $expected): void {
		$this->assertSame($expected, $this->call($route, $arguments));
	}

	/**
	 * The answer of a route, from the controller that has it.
	 *
	 * @param array<string, mixed> $arguments
	 * @return array{status: int, message: ?string, data: mixed}
	 */
	private function call(string $route, array $arguments): array {
		foreach (RouteTable::controllers() as $class) {
			foreach (RouteTable::methods($class) as $method) {
				if (RouteTable::key($method) === $route) {
					$controller = (new Application())->getContainer()->get($class);
					$this->assertInstanceOf(OCSController::class, $controller);
					return $this->ocs($controller, $method->getName(), $arguments);
				}
			}
		}
		$this->fail('No route ' . $route);
	}

	/**
	 * @return array<string, array{0: string, 1: int, 2: list<string>}>
	 */
	public static function reads(): array {
		$reads = [];
		foreach (self::READS as $route => [$status, $keys]) {
			$reads[$route] = [$route, $status, $keys];
		}
		return $reads;
	}

	/**
	 * @param list<string> $keys
	 */
	#[DataProvider('reads')]
	public function testReads(string $route, int $status, array $keys): void {
		$answer = $this->call($route, []);
		$this->assertSame($status, $answer['status']);
		$this->assertSame($keys, is_array($answer['data']) && !array_is_list($answer['data']) ? array_keys($answer['data']) : []);
	}

	public function testWrites(): void {
		$changed = $this->call('PUT /api/v1/checks/{id}', ['id' => 'password_spraying', 'params' => ['min_names' => 7]]);
		$this->assertSame([200, 'OK', 'password_spraying'], [$changed['status'], $changed['message'], $changed['data']['id']]);
		$reset = $this->call('POST /api/v1/checks/{id}/reset', ['id' => 'password_spraying']);
		$this->assertSame([200, array_keys($changed['data'])], [$reset['status'], array_keys($reset['data'])]);

		$level = $this->call('PUT /api/v1/protection-level', ['level' => 'strict']);
		$this->assertSame([200, ['level', 'checks'], 'strict'], [$level['status'], array_keys($level['data']), $level['data']['level']]);

		$ban = $this->call('POST /api/v1/bans', ['target' => '203.0.113.7', 'level' => 2, 'note' => ' scanner ']);
		$this->assertSame(200, $ban['status']);
		$this->assertSame(['203.0.113.7/32', 2, self::ADMIN, 'scanner', true], [$ban['data']['cidr'], $ban['data']['level'], $ban['data']['createdBy'], $ban['data']['note'], $ban['data']['active']]);
		$lifted = $this->call('DELETE /api/v1/bans/{id}', ['id' => $ban['data']['id'], 'note' => 'false alarm']);
		$this->assertSame([200, false, self::ADMIN, 'false alarm'], [$lifted['status'], $lifted['data']['active'], $lifted['data']['liftedBy'], $lifted['data']['liftNote']]);
		$again = $this->call('DELETE /api/v1/bans/{id}', ['id' => $ban['data']['id'], 'note' => 'twice']);
		$this->assertSame([200, 'false alarm'], [$again['status'], $again['data']['liftNote']]);

		$settings = $this->call('PUT /api/v1/settings', ['values' => ['ban_duration_1' => '2h']]);
		$this->assertSame([200, ['settings', 'templates']], [$settings['status'], array_keys($settings['data'])]);
		$this->assertSame(200, $this->call('POST /api/v1/settings/reset', [])['status']);

		$this->assertSame(200, $this->call('PUT /api/v1/learning', ['action' => 'start', 'days' => 25])['status']);
		$limit = $this->call('PUT /api/v1/learning', ['action' => 'extend', 'days' => 7]);
		$this->assertSame([400, 'days', 'learning_limit'], [$limit['status'], $limit['data']['param'], $limit['data']['reason']]);
		$this->assertStringStartsWith('Learning mode lasts at most 30 days in all, so that protection cannot stay off for long. This learning period started on ', $limit['data']['message']);
		$this->assertSame(200, $this->call('PUT /api/v1/learning', ['action' => 'stop'])['status']);
	}

	public function testWritesAreAudited(): void {
		$audited = [];
		$listener = static function (CriticalActionPerformedEvent $event) use (&$audited): void {
			// Detections are audited too: the reset switches the admin change check back on.
			if (!str_contains($event->getLogMessage(), ' detected (')) {
				$audited[] = [$event->getLogMessage(), $event->getParameters()];
			}
		};
		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->addListener(CriticalActionPerformedEvent::class, $listener);
		try {
			$this->call('PUT /api/v1/checks/{id}', ['id' => 'password_spraying', 'params' => ['min_names' => 7]]);
			$this->call('PUT /api/v1/checks/{id}', ['id' => 'password_spraying', 'params' => ['min_names' => 7]]);
			$this->call('POST /api/v1/checks/{id}/reset', ['id' => 'password_spraying']);
			$this->call('PUT /api/v1/checks/{id}', ['id' => 'password_spraying', 'params' => ['min_names' => 1]]);
			$ban = $this->call('POST /api/v1/bans', ['target' => '203.0.113.7', 'note' => 'scanner'])['data'];
			$this->call('POST /api/v1/bans', ['target' => '127.0.0.1']);
			$this->call('DELETE /api/v1/bans/{id}', ['id' => $ban['id'], 'note' => 'false alarm']);
			$this->call('DELETE /api/v1/bans/{id}', ['id' => $ban['id'], 'note' => 'twice']);
			$this->call('PUT /api/v1/settings', ['values' => ['protection_enabled' => false, 'ban_duration_1' => 7200]]);
			$this->call('POST /api/v1/settings/reset', []);
		} finally {
			$dispatcher->removeListener(CriticalActionPerformedEvent::class, $listener);
		}
		$reference = $ban['reference'];
		$this->assertSame([
			['Intrusion detection: check %s changed by %s: %s', ['check' => 'password_spraying', 'actor' => self::ADMIN, 'change' => '{"params":{"min_names":7}}']],
			['Intrusion detection: check %s reset to defaults by %s', ['check' => 'password_spraying', 'actor' => self::ADMIN]],
			['Intrusion detection: block %s (%s) added by %s: %s', ['reference' => $reference, 'cidr' => '203.0.113.7/32', 'actor' => self::ADMIN, 'note' => 'scanner']],
			['Intrusion detection: block %s (%s) lifted by %s: %s', ['reference' => $reference, 'cidr' => '203.0.113.7/32', 'actor' => self::ADMIN, 'note' => 'false alarm']],
			['Intrusion detection: intrusion detection turned %s by %s', ['state' => 'off', 'actor' => self::ADMIN]],
			['Intrusion detection: settings changed by %s: %s', ['actor' => self::ADMIN, 'change' => '{"protection_enabled":false,"ban_duration_1":7200}']],
			['Intrusion detection: all settings reset to defaults by %s', ['actor' => self::ADMIN]],
		], $audited);
	}

}
