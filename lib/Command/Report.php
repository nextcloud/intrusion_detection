<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReports;
use OCA\IntrusionDetection\Incident\InvalidIncidentQuery;
use OCA\IntrusionDetection\Incident\ReportFormat;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\L10N\IFactory;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes the incident report of an account or an address to standard
 * output, as JSON or as a printable HTML page. Like on the admin page, the
 * report is written to the audit log and not stored.
 */
class Report extends Base {
	public function __construct(
		private readonly IncidentReports $reports,
		private readonly ITimeFactory $timeFactory,
		private readonly IFactory $l10nFactory,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		$this->setName('intrusion:report')
			->setDescription('Write the incident report of an account or an address to standard output')
			->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'The account')
			->addOption('ip', null, InputOption::VALUE_REQUIRED, 'The address')
			->addOption('since', 's', InputOption::VALUE_REQUIRED, 'Start of the period: a date and time such as "2026-10-01 08:00" (UTC unless a zone is given) or a Unix time; default 7 days before the end')
			->addOption('until', null, InputOption::VALUE_REQUIRED, 'End of the period, in the same form; default now')
			->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'json or html', 'json');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$errors = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
		$user = $input->getOption('user');
		$ip = $input->getOption('ip');
		if (is_string($user) === is_string($ip)) {
			$errors->writeln('<error>Give exactly one of --user and --ip.</error>');
			return self::INVALID;
		}
		$format = ReportFormat::tryFrom((string)$input->getOption('format'));
		if ($format === null || $format === ReportFormat::Screen) {
			$errors->writeln('<error>The format must be json or html.</error>');
			return self::INVALID;
		}
		try {
			$since = self::time($input->getOption('since'));
			$until = self::time($input->getOption('until'));
		} catch (\InvalidArgumentException $e) {
			$errors->writeln('<error>' . $e->getMessage() . '</error>');
			return self::INVALID;
		}

		$l = $this->l10nFactory->get(Application::APP_ID);
		try {
			$now = $this->timeFactory->getTime();
			$query = is_string($user)
				? IncidentQuery::forUser($user, $since, $until, $now)
				: IncidentQuery::forAddress((string)$ip, $since, $until, $now);
		} catch (InvalidIncidentQuery $e) {
			$errors->writeln('<error>' . $e->describe($l) . '</error>');
			return self::INVALID;
		}

		$document = $this->reports->document($query, $format, ActorResolver::OCC, $l);
		$output->write($document['body'], false, OutputInterface::OUTPUT_RAW);
		return self::SUCCESS;
	}

	/**
	 * @throws \InvalidArgumentException
	 */
	private static function time(mixed $value): ?int {
		if (!is_string($value) || trim($value) === '') {
			return null;
		}
		$value = trim($value);
		if (preg_match('/^\d{1,12}$/', $value) === 1) {
			return (int)$value;
		}
		try {
			return (new \DateTimeImmutable($value))->getTimestamp();
		} catch (\Exception) {
			throw new \InvalidArgumentException('Not a date and time: ' . $value);
		}
	}
}
