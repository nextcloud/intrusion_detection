<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

/**
 * The files the firewall export can write into the export directory.
 */
enum ExportFormat: string {
	/** One range per line, with a comment giving the expiry and the reference */
	case Txt = 'txt';
	/** An nftables script that refills the sets of table `inet nextcloud_ids` */
	case Nft = 'nft';
	/** An `ipset restore` script that swaps in freshly filled sets */
	case Ipset = 'ipset';
	/** An append-only log of blocks and lifts, for fail2ban */
	case Log = 'log';

	public function fileName(): string {
		return 'bans.' . $this->value;
	}

	/**
	 * Whether the file is rewritten from the active blocks, rather than appended to.
	 */
	public function isSnapshot(): bool {
		return $this !== self::Log;
	}
}
