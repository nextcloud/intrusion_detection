<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Blocklists;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Blocklist\SourceEditor;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCP\L10N\IFactory;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Set extends Base {
	public function __construct(
		private readonly SourceEditor $editor,
		private readonly IFactory $l10nFactory,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:blocklists:set')
			->setDescription('Switch a list on or off, change its mode or interval, or add or remove your own list')
			->addArgument('id', InputArgument::REQUIRED, 'The list, e.g. spamhaus_drop_v4, or a new name for your own list')
			->addOption('enable', null, InputOption::VALUE_NONE, 'Switch the list on')
			->addOption('disable', null, InputOption::VALUE_NONE, 'Switch the list off')
			->addOption('mode', null, InputOption::VALUE_REQUIRED, 'For blocklists: protect (refuse requests) or observe (only count)')
			->addOption('interval', null, InputOption::VALUE_REQUIRED, 'Time between downloads, e.g. 6h; "default" for the list\'s default')
			->addOption('url', null, InputOption::VALUE_REQUIRED, 'Your own list: the https:// address to download')
			->addOption('purpose', null, InputOption::VALUE_REQUIRED, 'Your own list: deny, hosting or tor')
			->addOption('format', null, InputOption::VALUE_REQUIRED, 'Your own list: the file format (default cidr: one range per line)')
			->addOption('remove', null, InputOption::VALUE_NONE, 'Remove your own list');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$id = (string)$input->getArgument('id');
		$l = $this->l10nFactory->get('intrusion_detection');
		try {
			if ($input->getOption('remove')) {
				$this->editor->remove($id, 'occ');
				$output->writeln(sprintf('Removed %s.', $id));
				return self::SUCCESS;
			}
			$changes = [];
			if ($input->getOption('enable') || $input->getOption('disable')) {
				$changes['enabled'] = (bool)$input->getOption('enable');
			}
			foreach (['mode', 'url', 'purpose', 'format'] as $option) {
				if (is_string($input->getOption($option))) {
					$changes[$option] = (string)$input->getOption($option);
				}
			}
			$interval = $input->getOption('interval');
			if (is_string($interval)) {
				$changes['interval'] = $interval === 'default' ? null : ParamDefinition::parseDuration($interval);
			}
			$source = $this->editor->set($id, $changes, 'occ');
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($l) . '</error>');
			return self::INVALID;
		}
		$output->writeln(sprintf(
			'%s is %s%s. Download it now with: occ intrusion:blocklists:sync %s',
			$source->id,
			$source->enabled ? 'on' : 'off',
			$source->mode !== null ? ', mode ' . $source->mode : ', purpose ' . $source->purpose,
			$source->id,
		));
		return self::SUCCESS;
	}
}
