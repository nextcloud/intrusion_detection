<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Bans;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\InvalidBanException;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Lift a block. This always works, also when the administrator is locked out
 * of the web interface.
 */
class Lift extends Base {
	public function __construct(
		private readonly BanMapper $mapper,
		private readonly BanService $bans,
		private readonly AddressResolver $resolver,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:bans:lift')
			->setDescription('Lift a block, by its id, its reference or an address it covers')
			->addArgument('target', InputArgument::REQUIRED, 'Block id, reference (e.g. K7Q2-MPXA) or IP address')
			->addOption('note', null, InputOption::VALUE_REQUIRED, 'Why the block is lifted', '');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$target = trim((string)$input->getArgument('target'));
		$note = (string)$input->getOption('note');
		$bans = $this->find($target);
		if ($bans === []) {
			$output->writeln('<error>No active block matches ' . $target . '.</error>');
			return self::FAILURE;
		}
		foreach ($bans as $ban) {
			try {
				$this->bans->lift($ban, 'occ', $note);
			} catch (InvalidBanException $e) {
				$output->writeln('<error>' . $e->describe($this->l) . '</error>');
				return self::INVALID;
			}
			$output->writeln(sprintf('Lifted %s (%s).', $ban->getCidr(), $ban->getDisplayReference()));
		}
		return self::SUCCESS;
	}

	/**
	 * @return list<Ban>
	 */
	private function find(string $target): array {
		if (ctype_digit($target)) {
			try {
				return [$this->mapper->findById((int)$target)];
			} catch (DoesNotExistException) {
				return [];
			}
		}
		$source = SourceKey::tryFromIp($target);
		if ($source !== null) {
			return $this->resolver->activeBans($source);
		}
		try {
			return [$this->mapper->findByReference($target)];
		} catch (DoesNotExistException) {
			return [];
		}
	}
}
