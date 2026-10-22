<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Traps\TrapPaths as TrapPathList;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * List the trap paths, and add or remove custom ones, with the same
 * validation as the admin page.
 */
class TrapPaths extends Base {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly SettingsEditor $editor,
		private readonly AuditLogger $audit,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:trap-paths')
			->setDescription('List the trap paths, or add and remove your own')
			->addOption('add', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'A path such as /old-admin, exact; end it with * to match a prefix')
			->addOption('remove', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Remove one of your own paths');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$add = array_values(array_map('strval', (array)$input->getOption('add')));
		$remove = array_map('strtolower', array_values(array_map('strval', (array)$input->getOption('remove'))));
		if ($add !== [] || $remove !== []) {
			$paths = array_values(array_filter(
				array_merge($this->settings->paramList(TrapUrl::ID, 'paths'), $add),
				static fn (string $p): bool => !in_array(strtolower($p), $remove, true),
			));
			try {
				$this->editor->setParam(TrapUrl::ID, 'paths', $paths);
			} catch (InvalidParamException $e) {
				$output->writeln('<error>' . $e->describe($this->l) . '</error>');
				return self::INVALID;
			}
			$this->audit->log('trap paths changed by %s: added %s, removed %s', ['actor' => 'occ', 'added' => implode(', ', $add), 'removed' => implode(', ', $remove)]);
		}

		$data = [
			'builtin_enabled' => $this->settings->paramBool(TrapUrl::ID, 'builtin_enabled'),
			'builtin' => TrapPathList::BUILTIN,
			'autodiscover' => $this->settings->paramBool(TrapUrl::ID, 'autodiscover'),
			'custom' => $this->settings->paramList(TrapUrl::ID, 'paths'),
		];
		$data['need_rule'] = [];
		foreach ([TrapPathList::SERVER_NGINX, TrapPathList::SERVER_APACHE_FPM] as $server) {
			$data['need_rule'][$server] = TrapPathList::needingRule($server, $data['builtin_enabled'], $data['autodiscover'], $data['custom']);
		}
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $data);
			return self::SUCCESS;
		}
		$output->writeln('Built-in paths (' . ($data['builtin_enabled'] ? 'on' : 'off') . ', matched as prefixes): ' . implode(' ', $data['builtin']));
		$output->writeln(TrapPathList::AUTODISCOVER . ': ' . ($data['autodiscover'] ? 'on' : 'off')
			. ' (switch with occ intrusion:checks:set trap_url -p autodiscover=on)');
		$output->writeln($data['custom'] === [] ? 'No paths of your own.' : 'Your paths: ' . implode(' ', $data['custom']));
		$need = [];
		foreach ([TrapPathList::SERVER_NGINX => 'on nginx', TrapPathList::SERVER_APACHE_FPM => 'on Apache with PHP-FPM'] as $server => $label) {
			if ($data['need_rule'][$server] !== []) {
				$need[] = $label . ': ' . implode(' ', $data['need_rule'][$server]);
			}
		}
		if ($need !== []) {
			$output->writeln('Reach Nextcloud only with the web server rule from the Blocks tab, ' . implode('; ', $need) . '.');
		}
		return self::SUCCESS;
	}
}
