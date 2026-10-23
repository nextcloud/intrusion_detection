<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\BlocklistPresenter;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\SourceEditor;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The firewall export and the blocklists on the Blocks tab. Administrators
 * only; every change needs a recent password confirmation and is audited.
 *
 * The export directory is deliberately not settable here: it is read from
 * config.php only, so a web administrator cannot make Nextcloud write files
 * anywhere on the server.
 *
 * @psalm-import-type IntrusionDetectionFirewallExport from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBlocklists from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBlocklist from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSyncResult from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class BlocklistApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly BlocklistPresenter $presenter,
		private readonly SourceEditor $editor,
		private readonly SourceRepository $sources,
		private readonly BlocklistSync $sync,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * Show the firewall export
	 *
	 * The export directory from config.php, the formats, the last write or
	 * error, and the configuration snippets for nftables, ipset, fail2ban and
	 * systemd, filled in with the directory.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionFirewallExport, array{}>
	 *
	 * 200: Export returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/export')]
	public function export(): DataResponse {
		return new DataResponse($this->presenter->export($this->l));
	}

	/**
	 * List the blocklists and network lists
	 *
	 * Every built-in and custom list with its sync status and its matches per day.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBlocklists, array{}>
	 *
	 * 200: Lists returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/blocklists')]
	public function lists(): DataResponse {
		return new DataResponse($this->presenter->lists($this->l));
	}

	/**
	 * Add a custom list
	 *
	 * The address must be https:// and outside the local network; it is
	 * checked when the list is saved and before every download.
	 *
	 * @param string $id A short name: a lower-case letter, then letters, digits or underscores
	 * @param string $url Where to download the list
	 * @param 'deny'|'hosting'|'tor' $purpose Block the addresses, or mark them as hosting or Tor networks
	 * @param string $fileFormat The file format, usually "cidr" (one range per line); not called "format", which chooses the OCS response format
	 * @param 'observe'|'protect' $mode For blocklists: only count matches, or refuse them
	 * @param int<900, 604800>|null $interval Seconds between downloads; null for the global interval
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBlocklist, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: List added
	 * 400: A value is not valid, or the list exists already
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/blocklists')]
	#[PasswordConfirmationRequired]
	public function create(string $id, string $url, string $purpose, string $fileFormat = 'cidr', string $mode = BlocklistSource::MODE_OBSERVE, ?int $interval = null): DataResponse {
		$id = trim($id);
		if ($this->sources->get($id) !== null) {
			return $this->error($this->l->t('A list with this name exists already.'), 'id', 'list_exists');
		}
		$this->editor->set($id, [
			'url' => trim($url),
			'purpose' => $purpose,
			'format' => $fileFormat,
			'mode' => $mode,
			'interval' => $interval,
			'enabled' => true,
		], $this->actor());
		return $this->one($id);
	}

	/**
	 * Change a list
	 *
	 * Switch it on or off, choose the mode of a blocklist, or its interval.
	 *
	 * @param string $id The list
	 * @param bool|null $enabled Download and use the list
	 * @param 'observe'|'protect'|null $mode For blocklists: only count matches, or refuse them
	 * @param int<0, 604800>|null $interval Seconds between downloads; 0 for the default interval
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBlocklist, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The list does not exist
	 *
	 * 200: List changed
	 * 400: A value is not valid
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/blocklists/{id}', requirements: ['id' => '[a-z][a-z0-9_]{1,31}'])]
	#[PasswordConfirmationRequired]
	public function update(string $id, ?bool $enabled = null, ?string $mode = null, ?int $interval = null): DataResponse {
		$this->existing($id);
		$changes = [];
		if ($enabled !== null) {
			$changes['enabled'] = $enabled;
		}
		if ($mode !== null) {
			$changes['mode'] = $mode;
		}
		if ($interval !== null) {
			$changes['interval'] = $interval === 0 ? null : $interval;
		}
		$this->editor->set($id, $changes, $this->actor());
		return $this->one($id);
	}

	/**
	 * Remove a custom list
	 *
	 * Built-in lists cannot be removed; switch them off instead.
	 *
	 * @param string $id The list
	 * @return DataResponse<Http::STATUS_OK, array{removed: string}, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The list does not exist
	 *
	 * 200: List removed
	 * 400: The list is built in
	 */
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/blocklists/{id}', requirements: ['id' => '[a-z][a-z0-9_]{1,31}'])]
	#[PasswordConfirmationRequired]
	public function remove(string $id): DataResponse {
		$this->existing($id);
		$this->editor->remove($id, $this->actor());
		return new DataResponse(['removed' => $id]);
	}

	/**
	 * Download a list now
	 *
	 * Only enabled lists can be downloaded. The previous version stays in use
	 * when the download fails.
	 *
	 * @param string $id The list
	 * @return DataResponse<Http::STATUS_OK, array{result: IntrusionDetectionSyncResult, list: IntrusionDetectionBlocklist}, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The list does not exist
	 *
	 * 200: Download finished; the result says whether it worked
	 * 400: The list is switched off
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/blocklists/{id}/sync', requirements: ['id' => '[a-z][a-z0-9_]{1,31}'])]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 300)]
	public function syncNow(string $id): DataResponse {
		$source = $this->existing($id);
		if (!$source->enabled) {
			return $this->error($this->l->t('Switch the list on before downloading it.'), 'enabled', 'list_disabled');
		}
		$results = $this->sync->sync($id);
		$result = $results[0] ?? null;
		if ($result === null) {
			return $this->error($this->l->t('The list could not be downloaded.'), null, 'sync_failed');
		}
		$this->audit->log('blocklist %s downloaded by %s: %s', ['list' => $id, 'actor' => $this->actor(), 'outcome' => $result->outcome]);
		$list = $this->presenter->list($id, $this->l);
		if ($list === null) {
			throw new OCSNotFoundException($this->l->t('There is no list "%s".', [$id]));
		}
		return new DataResponse(['result' => BlocklistPresenter::syncResult($result, $this->l, $source->url), 'list' => $list]);
	}

	/**
	 * @throws OCSNotFoundException
	 */
	private function existing(string $id): BlocklistSource {
		return $this->sources->get($id) ?? throw new OCSNotFoundException($this->l->t('There is no list "%s".', [$id]));
	}

	/**
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBlocklist, array{}>
	 * @throws OCSNotFoundException
	 */
	private function one(string $id): DataResponse {
		$list = $this->presenter->list($id, $this->l) ?? throw new OCSNotFoundException($this->l->t('There is no list "%s".', [$id]));
		return new DataResponse($list);
	}

}
