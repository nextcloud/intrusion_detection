<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Files\Folder;
use OCP\Files\IMimeTypeLoader;
use OCP\Files\IRootFolder;
use OCP\IDBConnection;
use Psr\Log\LoggerInterface;

/**
 * Whether a share reaches enough files to be a sensitive action (concept
 * section 11.13): the account's whole folder, or a folder with more than
 * `sensitive_share_min_files` files, decided by the share request's path.
 *
 * Only asked for public links and federated shares in a session that must
 * confirm sensitive actions. Counting stops at the limit: one query on the
 * file cache that reads at most limit + 1 rows of the folder's storage.
 * Files of storages mounted inside the folder (other shares, external
 * storage) are not counted.
 */
class ShareSize {
	public function __construct(
		private readonly IRootFolder $rootFolder,
		private readonly IDBConnection $db,
		private readonly IMimeTypeLoader $mimeTypes,
		private readonly Settings $settings,
		private readonly LoggerInterface $logger,
	) {
	}

	public function isLarge(string $uid, string $path): bool {
		try {
			$userFolder = $this->rootFolder->getUserFolder($uid);
			$path = '/' . trim($path, '/');
			if ($path === '/') {
				return true;
			}
			$node = $userFolder->get($path);
			if (!$node instanceof Folder) {
				return false;
			}
			if ($node->getPath() === $userFolder->getPath()) {
				return true;
			}
			return $this->countFiles($node, $this->settings->getInt(GlobalSettings::SENSITIVE_SHARE_MIN_FILES) + 1) > $this->settings->getInt(GlobalSettings::SENSITIVE_SHARE_MIN_FILES);
		} catch (\Throwable $e) {
			// The share request fails on its own for a path that does not exist.
			$this->logger->debug('Intrusion detection could not size a share', ['exception' => $e]);
			return false;
		}
	}

	/**
	 * Files below the folder in its own storage, counted up to a limit.
	 */
	private function countFiles(Folder $folder, int $limit): int {
		$storageId = $folder->getStorage()->getCache()->getNumericStorageId();
		$internal = $folder->getInternalPath();
		$qb = $this->db->getQueryBuilder();
		$qb->select('fileid')
			->from('filecache')
			->where($qb->expr()->eq('storage', $qb->createNamedParameter($storageId, IQueryBuilder::PARAM_INT)))
			->andWhere($qb->expr()->neq('mimetype', $qb->createNamedParameter($this->mimeTypes->getId('httpd/unix-directory'), IQueryBuilder::PARAM_INT)))
			->setMaxResults($limit);
		if ($internal !== '') {
			$qb->andWhere($qb->expr()->like('path', $qb->createNamedParameter($this->db->escapeLikeParameter($internal) . '/%')));
		}
		$result = $qb->executeQuery();
		$count = 0;
		while ($result->fetchOne() !== false) {
			$count++;
		}
		$result->closeCursor();
		return $count;
	}
}
