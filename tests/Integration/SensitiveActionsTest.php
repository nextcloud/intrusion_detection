<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Sensitive\SensitiveActions;
use OCA\IntrusionDetection\Sensitive\SensitiveRoutes;
use OCA\IntrusionDetection\Sensitive\ShareSize;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\Authentication\Token\IToken;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Files\Cache\ICache;
use OCP\Files\File;
use OCP\Files\Folder;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\Files\IUserFolder;
use OCP\Files\Node;
use OCP\Files\NotFoundException;
use OCP\Files\Storage\IStorage;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Sensitive actions in risky sessions (concept section 11.13), decided by
 * the session-state rule with real settings, sessions and files.
 */
#[Group('DB')]
class SensitiveActionsTest extends SensitiveTestCase {
	/** A storage id no real storage has */
	private const STORAGE = 987654321;

	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-sensitive', 'alice@example.com');
		$this->startSession($this->alice);
		$this->route = 'settings.authsettings.create';
		$this->headers = ['Accept' => 'application/json', 'X-Requested-With' => 'XMLHttpRequest', 'Referer' => 'https://cloud.example.com/index.php/settings/user/security'];
	}

	public function testOtherRoutesCostOneLookupAndNothingElse(): void {
		$this->route = 'files.view.index';
		$this->riskyLogin();
		$this->assertNull($this->check());
		$this->assertNull($this->sensitiveRule()->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')), 'WebDAV has no sensitive actions');
	}

	public function testANormalSessionGoesAhead(): void {
		$this->assertNull($this->check());
	}

	public function testARiskySessionMustConfirmFirstAndComesBackToItsPage(): void {
		$this->riskyLogin();
		$block = $this->check();
		$this->assertNotNull($block);
		$this->assertSame(SessionBlock::CONFIRMATION_REQUIRED, $block->error);
		$this->assertSame(SessionBlock::CONFIRMATION_HEADER, $block->davHeader);
		$url = (string)$block->data['url'];
		$this->assertStringContainsString('/apps/intrusion_detection/confirm', $url);
		parse_str((string)parse_url($url, PHP_URL_QUERY), $query);
		$this->assertSame('/index.php/settings/user/security', $query['redirect_url'] ?? null, 'Back to the page the request came from');
		$this->assertSame('Confirm', $block->data['dialog']['confirm'] ?? null);
	}

	public function testAPageOpenedInTheBrowserIsTheWayBack(): void {
		$this->riskyLogin();
		$this->method = 'GET';
		$this->headers = ['Accept' => 'text/html'];
		parse_str((string)parse_url((string)$this->check()?->redirectUrl, PHP_URL_QUERY), $query);
		$this->assertSame('/index.php/apps/files/', $query['redirect_url'] ?? null);
	}

	public function testAnotherServerIsNeverTheWayBack(): void {
		$this->riskyLogin();
		$this->headers['Referer'] = 'https://evil.example/index.php/settings/user/security';
		$this->assertStringNotContainsString('redirect_url', (string)$this->check()?->data['url']);
	}

	public function testAConfirmationLetsActionsThroughForItsTime(): void {
		$this->riskyLogin();
		$this->sensitiveSession()->confirmed($this->state, $this->alice->getUID(), 'email_code');
		$this->assertNull($this->check());
		$confirmed = $this->state->get(SessionState::SENSITIVE);
		$this->state->set(SessionState::SENSITIVE, ['confirmedAt' => (int)$confirmed['confirmedAt'] - 601] + $confirmed);
		$this->assertNotNull($this->check(), 'After sensitive_confirm_ttl it is asked again');
	}

	public function testAGroupSwitchedOffIsNotProtected(): void {
		$this->riskyLogin();
		$this->settings->setGlobal(GlobalSettings::SENSITIVE_GROUPS, [SensitiveRoutes::GROUP_ACCOUNT]);
		$this->assertNull($this->check());
		$this->route = 'settings.changepassword.changepersonalpassword';
		$this->assertNotNull($this->check());
	}

	public function testAnAdministratorConfirmsAgainAfterTheMaxAge(): void {
		Server::get(IGroupManager::class)->get('admin')?->addUser($this->alice);
		try {
			$this->route = 'ocs.provisioning_api.users.adduser';
			$this->assertNotNull($this->check(), 'No strong confirmation in this session yet');
			$this->sensitiveSession()->strongConfirmation($this->state, $this->alice->getUID());
			$this->assertNull($this->check(), 'The second factor was solved just now');
			$this->settings->setGlobal(GlobalSettings::SENSITIVE_ADMINS_ALWAYS, false);
			$this->state->remove(SessionState::SENSITIVE);
			$this->assertNull($this->check(), 'Switched off');
		} finally {
			Server::get(IGroupManager::class)->get('admin')?->removeUser($this->alice);
		}
	}

	public function testSharesCountForTheWholeAccountOrALargeFolderOnly(): void {
		$this->riskyLogin();
		$this->settings->setGlobal(GlobalSettings::SENSITIVE_SHARE_MIN_FILES, 2);
		$this->cacheEntry('files/small/a.txt');
		$this->cacheEntry('files/large/sub', true);
		$this->cacheEntry('files/large/sub/b.txt');
		$this->cacheEntry('files/large/c.txt');
		$this->cacheEntry('files/large/d.txt');
		$this->cacheEntry('files/larger-sibling/e.txt');
		$this->route = 'ocs.files_sharing.shareapi.createshare';

		$this->params = ['path' => '/', 'shareType' => 3];
		$this->assertNotNull($this->check(), 'A public link of everything');
		$this->params = ['path' => '/large', 'shareType' => 3];
		$this->assertNotNull($this->check(), 'Three files are more than two; the folder in it does not count');
		$this->params = ['path' => '/large', 'shareType' => 6];
		$this->assertNotNull($this->check(), 'Federated, too');
		$this->params = ['path' => '/small', 'shareType' => 3];
		$this->assertNull($this->check());
		$this->params = ['path' => '/large/c.txt', 'shareType' => 3];
		$this->assertNull($this->check(), 'A single file');
		$this->params = ['path' => '/', 'shareType' => 0];
		$this->assertNull($this->check(), 'A share with someone on this server');
		$this->params = ['path' => '/missing', 'shareType' => 3];
		$this->assertNull($this->check(), 'The request fails on its own');
		$this->settings->setGlobal(GlobalSettings::SENSITIVE_SHARE_MIN_FILES, 3);
		$this->params = ['path' => '/large', 'shareType' => 3];
		$this->assertNull($this->check(), 'Not more than three');
	}

	public function testWithoutAWayToConfirmTheActionIsRefusedByDefault(): void {
		$bob = $this->user('ids-sensitive-bob', null);
		$this->startSession($bob);
		$this->riskyLogin($bob);
		$this->assertNotNull($this->check());
	}

	public function testOrAllowedWithANoticeToTheAdministrators(): void {
		$bob = $this->user('ids-sensitive-bob', null);
		$this->startSession($bob);
		$this->riskyLogin($bob);
		$this->settings->setGlobal(GlobalSettings::SENSITIVE_NO_METHOD, 'allow_notify');
		$this->assertNull($this->check());
		$this->assertNotSame([], $this->notificationsFor('admin', AdminNotices::SUBJECT_SENSITIVE_UNCONFIRMED));
		$this->assertContains('Intrusion detection: sensitive action of ' . $bob->getUID() . ' (devices) allowed without confirmation: the account cannot confirm', $this->audited);

		$this->riskyLogin();
		$this->assertNotNull($this->checkFor($this->alice), 'Accounts that can confirm still must');
	}

	public function testDuringLockdownNewDevicesAreRefusedEvenInAConfirmedSession(): void {
		Server::get(LockdownService::class)->start(3600, 'test', 'admin');
		$this->sensitiveSession()->confirmed($this->state, $this->alice->getUID(), 'email_code');
		$block = $this->check();
		$this->assertSame(SensitiveActions::ERROR_DEVICES_LOCKED, $block?->error);
		$this->assertSame('New devices cannot be connected right now. Please try again later.', $block?->data['message'] ?? null);
		$this->route = 'core.clientflowloginv2.generateapppassword';
		$this->assertSame(SensitiveActions::ERROR_DEVICES_LOCKED, $this->check()?->error);
		$this->route = 'settings.changepassword.changepersonalpassword';
		$this->assertNull($this->check(), 'Other actions only need the confirmation the session has');
	}

	public function testADetectionMarksItsOwnSession(): void {
		$detection = $this->detection();
		$outcome = $this->handler()->apply(new ResponseContext(
			new DetectionDraft(DirectoryScraping::ID, uid: $this->alice->getUID(), sessionTokenId: $this->currentSession->tokenId()),
			$detection,
			Server::get(CheckRegistry::class)->get(DirectoryScraping::ID),
			true,
		));
		$this->assertTrue($outcome->enforced);
		$this->assertSame(DirectoryScraping::ID, $this->state->get(SessionState::RISKY)['check'] ?? null);
		$this->assertSame(0, $this->markedRows(), 'Nothing in the database for the request\'s own session');
		$this->assertNotNull($this->check());
	}

	public function testADetectionAboutAnotherSessionMarksItInTheDatabase(): void {
		$other = $this->token($this->alice, IToken::TEMPORARY_TOKEN, 'Chrome on Windows');
		$this->sessionUser = null;
		$outcome = $this->handler()->apply(new ResponseContext(
			new DetectionDraft(DirectoryScraping::ID, uid: $this->alice->getUID(), sessionTokenId: $other['id']),
			$this->detection(),
			Server::get(CheckRegistry::class)->get(DirectoryScraping::ID),
			true,
		));
		$this->assertSame(['session' => $other['id']], $outcome->ref);
		$this->assertSame(1, $this->markedRows());

		$this->assertNull($this->checkFor($this->alice), 'The first session is not the one marked');
		$this->session->id = $other['secret'];
		$this->assertNotNull($this->checkFor($this->alice), 'The marked session must confirm');

		Server::get(IUserManager::class)->get($this->alice->getUID())?->delete();
		$this->assertSame(0, $this->markedRows(), 'Removed with the account');
	}

	public function testDirectoryScrapingOffersTheResponse(): void {
		$this->assertContains(ResponseType::ConfirmSensitive, Server::get(CheckRegistry::class)->get(DirectoryScraping::ID)->responses);
	}

	protected function tearDown(): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete('filecache')->where($qb->expr()->eq('storage', $qb->createNamedParameter(self::STORAGE, IQueryBuilder::PARAM_INT)))->executeStatement();
		parent::tearDown();
	}

	/**
	 * The account's files, as the file cache knows them, without mounting
	 * anything: one storage, `files/` its home folder.
	 */
	#[\Override]
	protected function actions(): SensitiveActions {
		$storage = $this->createMock(IStorage::class);
		$cache = $this->createMock(ICache::class);
		$cache->method('getNumericStorageId')->willReturn(self::STORAGE);
		$storage->method('getCache')->willReturn($cache);
		$folder = function (string $path, string $class = Folder::class) use ($storage): Folder {
			/** @var Folder&MockObject $node */
			$node = $this->createMock($class);
			$node->method('getPath')->willReturn('/alice/files' . ($path === '' ? '' : '/' . $path));
			$node->method('getInternalPath')->willReturn('files' . ($path === '' ? '' : '/' . $path));
			$node->method('getStorage')->willReturn($storage);
			return $node;
		};
		$home = $folder('', IUserFolder::class);
		$home->method('get')->willReturnCallback(fn (string $path): Node => match (trim($path, '/')) {
			'large' => $folder('large'),
			'small' => $folder('small'),
			'large/c.txt' => $this->createMock(File::class),
			default => throw new NotFoundException(),
		});
		$root = $this->createMock(IRootFolder::class);
		$root->method('getUserFolder')->willReturn($home);
		$this->shareSize = new ShareSize($root, $this->db, Server::get(IMimeTypeLoader::class), $this->settings, Server::get(LoggerInterface::class));
		return parent::actions();
	}

	private function cacheEntry(string $path, bool $folder = false): void {
		$mimeTypes = Server::get(IMimeTypeLoader::class);
		$this->db->insertIfNotExist('*PREFIX*filecache', [
			'storage' => self::STORAGE,
			'path' => $path,
			'path_hash' => md5($path),
			'parent' => -1,
			'name' => basename($path),
			'mimetype' => $mimeTypes->getId($folder ? 'httpd/unix-directory' : 'text/plain'),
			'mimepart' => $mimeTypes->getId($folder ? 'httpd' : 'text'),
			'size' => 1,
			'mtime' => 1,
			'storage_mtime' => 1,
			'encrypted' => 0,
			'unencrypted_size' => 0,
			'etag' => 'etag',
			'permissions' => 31,
		], ['storage', 'path_hash']);
	}

	private function check(): ?SessionBlock {
		return $this->checkFor($this->sessionUser ?? $this->alice);
	}

	private function checkFor(IUser $user): ?SessionBlock {
		$this->sessionUser = $user;
		return $this->sensitiveRule()->check($this->state, RequestTarget::app($this->createMock(\OCP\AppFramework\Controller::class), 'create', $this->method, '/index.php/apps/files/'));
	}

	/**
	 * The session's login was allowed without a confirmation.
	 */
	private function riskyLogin(?IUser $user = null): void {
		$this->state->set(SessionState::CONFIRMATION, ['uid' => ($user ?? $this->alice)->getUID(), 'by' => 'none', 'policies' => ['risky_network'], 'at' => time()]);
	}

	private function detection(): Detection {
		$detection = new Detection();
		$detection->setId(4242);
		return $detection;
	}
}
