<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCP\IGroupManager;

/**
 * Whether a password login comes from a hosting provider's or the Tor
 * network (concept section 10.17).
 *
 * The attributes come from the verdict the address check already has for
 * the request ({@see \OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider}),
 * so an address without them costs nothing. Only for an address with an
 * attribute are the office networks, the exempt groups and the user's
 * trusted networks consulted, in that order. The answer is kept per login,
 * as the check and its step-up reason both ask.
 */
class NetworkAttributes {
	/** @var \WeakMap<LoginContext, ?RiskyLogin>|null */
	private ?\WeakMap $answers = null;

	public function __construct(
		private readonly Settings $settings,
		private readonly RequestContext $context,
		private readonly AddressCache $addressCache,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITrustedNetworks $trustedNetworks,
		private readonly IGroupManager $groupManager,
	) {
	}

	/**
	 * Why the login is a risky-network login, or null when it is not.
	 */
	public function riskyLogin(LoginContext $login): ?RiskyLogin {
		$this->answers ??= new \WeakMap();
		if (!$this->answers->offsetExists($login)) {
			$this->answers[$login] = $this->evaluate($login);
		}
		return $this->answers[$login];
	}

	private function evaluate(LoginContext $login): ?RiskyLogin {
		$source = $login->source;
		$verdict = $source === null ? null : $this->verdict($source->ip);
		if ($source === null || $verdict === null) {
			return null;
		}
		$attributes = array_values(array_filter(
			[BlocklistSource::PURPOSE_TOR, BlocklistSource::PURPOSE_HOSTING],
			static fn (string $attribute): bool => $verdict->hasAttribute($attribute),
		));
		if ($attributes === []) {
			return null;
		}
		if (RangeCodec::firstContaining($this->list(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS), $source) !== null) {
			return null;
		}
		foreach ($this->list(GlobalSettings::RISKY_NETWORK_EXEMPT_GROUPS) as $group) {
			if ($this->groupManager->isInGroup($login->uid(), $group)) {
				return null;
			}
		}
		if ($this->trustedNetworks->isTrusted($login->uid(), $source)) {
			return null;
		}
		$lists = [];
		foreach ($verdict->attributes as $attribute) {
			if (str_starts_with($attribute, BlocklistSource::NETWORK_ATTRIBUTE_PREFIX)) {
				$lists[] = substr($attribute, strlen(BlocklistSource::NETWORK_ATTRIBUTE_PREFIX));
			}
		}
		return new RiskyLogin($attributes, $lists);
	}

	/**
	 * The verdict of the request's own address, from the address check or
	 * the cache. A login is always judged on the address it came from.
	 */
	private function verdict(string $ip): ?Verdict {
		$current = $this->addresses->current();
		if ($current === null || $current->ip !== $ip) {
			return null;
		}
		return $this->context->verdict() ?? $this->addressCache->get($current);
	}

	/**
	 * @return list<string>
	 */
	private function list(string $setting): array {
		$value = $this->settings->global($setting);
		return is_array($value) ? $value : [];
	}
}
