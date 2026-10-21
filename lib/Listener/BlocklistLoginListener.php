<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * Records a failed login from an address on a blocklist that did not refuse
 * it (a list in Observe, or the check observing).
 *
 * The lists come from the verdict the address check already has for this
 * request, so this adds no lookup. The login name and password are never
 * read.
 *
 * @template-implements IEventListener<AnyLoginFailedEvent>
 */
class BlocklistLoginListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly RequestContext $context,
		private readonly AddressCache $cache,
		private readonly CheckRegistry $registry,
		private readonly SourceRepository $sources,
		private readonly ResponseEngine $engine,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof AnyLoginFailedEvent || !$this->settings->modeState(BlocklistMatch::ID)->runs()) {
			return;
		}
		try {
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isIgnored($source)) {
				return;
			}
			$verdict = $this->context->verdict() ?? $this->cache->get($source);
			if ($verdict === null) {
				return;
			}
			$lists = [];
			foreach (BlocklistMatch::listsOf($verdict) as $id) {
				$lists[$id] = $this->sources->get($id)?->name ?? $id;
			}
			if ($lists === []) {
				return;
			}
			$check = $this->registry->check(BlocklistMatch::class);
			$this->engine->handle($check->failedLoginDraft($source, $lists, $this->request->getHeader('User-Agent')));
		} catch (\Throwable $e) {
			// A failure here must never break the login path.
			$this->logger->error('Intrusion detection could not record a failed login from a listed address', ['exception' => $e]);
		}
	}
}
