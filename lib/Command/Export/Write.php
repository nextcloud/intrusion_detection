<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Export;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Export\ExportDirectory;
use OCA\IntrusionDetection\Export\ExportException;
use OCA\IntrusionDetection\Export\FirewallExporter;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Write extends Base {
	public function __construct(
		private readonly FirewallExporter $exporter,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:export:write')
			->setDescription('Write the firewall export files now (bans.txt, bans.nft, bans.ipset)');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		if ($this->exporter->formats() === []) {
			$output->writeln('<comment>No export format is switched on.</comment> Set export_formats, e.g.: occ config:app:set intrusion_detection export_formats --type=array --value=\'["nft","log"]\'');
			return self::FAILURE;
		}
		try {
			$status = $this->exporter->write();
		} catch (ExportException $e) {
			$output->writeln('<error>Nothing written: ' . self::describe($e->reason) . '</error>');
			return self::FAILURE;
		}
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $status->toArray());
			return self::SUCCESS;
		}
		$output->writeln(sprintf('Wrote %d block(s) to %s: %s.', $status->entries, (string)$status->directory, implode(', ', $status->toArray()['files'])));
		return self::SUCCESS;
	}

	public static function describe(string $reason): string {
		return match ($reason) {
			ExportException::NOT_CONFIGURED => 'set ' . ExportDirectory::CONFIG_KEY . ' in config.php to a directory the web server can write to',
			ExportException::NOT_ABSOLUTE => 'the export directory must be an absolute path',
			ExportException::NOT_FOUND => 'the export directory does not exist',
			ExportException::NOT_A_DIRECTORY => 'the export directory is not a directory',
			ExportException::INSIDE_DATA_DIRECTORY => 'the export directory must not be inside the data directory',
			ExportException::INSIDE_WEB_ROOT => 'the export directory must not be inside the Nextcloud installation or an apps directory, nor contain it',
			ExportException::WORLD_WRITABLE => 'the export directory must not be writable by every user',
			ExportException::NOT_WRITABLE => 'the web server user cannot write to the export directory',
			default => 'a file could not be written',
		};
	}
}
