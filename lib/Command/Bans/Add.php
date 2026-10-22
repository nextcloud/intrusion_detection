<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Bans;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Response\BanService;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Add extends Base {
	public function __construct(
		private readonly BanService $bans,
		private readonly AuditLogger $audit,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:bans:add')
			->setDescription('Block an address (IPv4), a /24 (IPv4) or a /64 (IPv6) by hand')
			->addArgument('target', InputArgument::REQUIRED, 'e.g. 203.0.113.7, 203.0.113.0/24 or 2001:db8:1:2::/64')
			->addOption('level', null, InputOption::VALUE_REQUIRED, 'Escalation level 1-3, which sets the duration', '1')
			->addOption('duration', null, InputOption::VALUE_REQUIRED, 'A duration instead of the level\'s, e.g. 12h')
			->addOption('note', null, InputOption::VALUE_REQUIRED, 'Why the address is blocked');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$level = (string)$input->getOption('level');
		if (!in_array($level, ['1', '2', '3'], true)) {
			$output->writeln('<error>The level must be 1, 2 or 3.</error>');
			return self::INVALID;
		}
		try {
			$duration = is_string($input->getOption('duration')) ? ParamDefinition::parseDuration((string)$input->getOption('duration')) : null;
			if ($duration !== null && ($duration <= 0 || $duration > BanService::MAX_DURATION)) {
				$output->writeln('<error>A block lasts more than 0 seconds and at most 90 days.</error>');
				return self::INVALID;
			}
			$note = is_string($input->getOption('note')) ? (string)$input->getOption('note') : null;
			$ban = $this->bans->banManually((string)$input->getArgument('target'), (int)$level, 'occ', $note, $duration);
		} catch (InvalidParamException|\InvalidArgumentException $e) {
			$output->writeln('<error>' . $e->getMessage() . '</error>');
			return self::INVALID;
		}
		$this->audit->log('block %s (%s) added by %s: %s', ['reference' => $ban->getDisplayReference(), 'cidr' => $ban->getCidr(), 'actor' => 'occ', 'note' => $note]);
		$output->writeln(sprintf('Blocked %s until %s (reference %s).', $ban->getCidr(), date('c', $ban->getExpiresAt()), $ban->getDisplayReference()));
		return self::SUCCESS;
	}
}
