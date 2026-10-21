<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Decoys;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Create a decoy credential and print its secret, the only time it is shown.
 */
class Create extends Base {
	public function __construct(
		private readonly DecoyService $decoys,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:decoys:create')
			->setDescription('Create a decoy app password or token; the secret is shown once')
			->addOption('label', null, InputOption::VALUE_REQUIRED, 'Where you will plant it, e.g. "old backup script on nas01"')
			->addOption('login-name', null, InputOption::VALUE_REQUIRED, 'An account name to plant with it; must not be an existing account')
			->addOption('format', null, InputOption::VALUE_REQUIRED, 'app-password (5 groups of 5 characters) or token (72 characters)', DecoyFormat::AppPassword->value);
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$format = DecoyFormat::tryFrom((string)$input->getOption('format'));
		if ($format === null) {
			$output->writeln('<error>The format must be app-password or token.</error>');
			return self::INVALID;
		}
		$loginName = $input->getOption('login-name');
		try {
			[$decoy, $secret] = $this->decoys->create((string)$input->getOption('label'), is_string($loginName) ? $loginName : null, $format, 'occ');
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}

		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $decoy->jsonSerialize() + ['secret' => $secret]);
			return self::SUCCESS;
		}
		$output->writeln('Decoy ' . $decoy->getId() . ' ("' . $decoy->getLabel() . '") created.');
		$output->writeln('');
		$output->writeln('  Secret:       <info>' . $secret . '</info>');
		if ($decoy->getLoginName() !== null) {
			$output->writeln('  Account name: <info>' . $decoy->getLoginName() . '</info>');
		}
		$output->writeln('');
		$output->writeln('This is the only time the secret is shown; Nextcloud keeps only a fingerprint of it.');
		$output->writeln('Plant it where only an intruder would look, for example in an old script on a file server,');
		$output->writeln('a wiki page about backups, or a note in a shared drive. Anyone who uses it found it there:');
		$output->writeln('their address is blocked for 7 days at once and you are notified.');
		return self::SUCCESS;
	}
}
