<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Settings;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Notification\UserLinks;
use OCA\IntrusionDetection\Personal\ManageSummary;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\Settings\Personal;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCP\AppFramework\Services\IInitialState;
use OCP\IL10N;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class PersonalTest extends TestCase {
	/** @var Settings&MockObject */
	private Settings $settings;
	/** @var IInitialState&MockObject */
	private IInitialState $state;
	/** @var PersonalOverview&MockObject */
	private PersonalOverview $overview;
	private bool $master = true;
	private bool $page = true;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(Settings::class);
		$this->settings->method('isEnabled')->willReturnCallback(fn (): bool => $this->master);
		$this->settings->method('getBool')->willReturnCallback(fn (string $name): bool => $name === GlobalSettings::PERSONAL_PAGE_ENABLED ? $this->page : false);
		$this->settings->method('personalPageEnabled')->willReturnCallback(fn (): bool => $this->master && $this->page);
		$this->state = $this->createMock(IInitialState::class);
		$this->overview = $this->createMock(PersonalOverview::class);
	}

	public function testTheSectionComesWithItsOverviewAndTheAnchorOfTheUserLinks(): void {
		$this->overview->method('get')->willReturn(['status' => ['level' => 'ok']]);
		$this->state->expects($this->once())->method('provideInitialState')->with('personal', $this->callback(
			static fn (array $data): bool => $data['overview'] === ['status' => ['level' => 'ok']]
				&& $data['manage'] === ['devices' => 1, 'networks' => 0, 'otherBrowsers' => 2]
				&& $data['staleCredentials'] === [['id' => 7, 'name' => 'Thunderbird', 'kind' => 'app_password', 'lastUsed' => 1000]],
		));

		$response = $this->personal()->getForm();

		$this->assertSame('settings-personal', $response->getTemplateName());
		$this->assertStringContainsString('id="' . UserLinks::ANCHOR . '"', $response->render());
	}

	public function testItSitsInTheSecuritySectionAfterCoresDevicesAndSessions(): void {
		$personal = $this->personal();
		$this->assertSame('security', $personal->getSection());
		$this->assertGreaterThan(100, $personal->getPriority());
	}

	/**
	 * @return array<string, array{bool, bool}>
	 */
	public static function hidden(): array {
		return [
			'the page is switched off' => [true, false],
			'intrusion detection is switched off' => [false, true],
		];
	}

	#[DataProvider('hidden')]
	public function testNothingIsShownWhenSwitchedOff(bool $master, bool $page): void {
		$this->master = $master;
		$this->page = $page;
		$this->state->expects($this->never())->method('provideInitialState');
		$this->overview->expects($this->never())->method('get');

		$personal = $this->personal();
		$response = $personal->getForm();

		$this->assertFalse($personal->isVisible());
		$this->assertSame('settings/empty', $response->getTemplateName());
		$this->assertSame('settings', $response->getApp());
	}

	private function personal(): Personal {
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($this->createMock(IUser::class));
		$manage = $this->createMock(ManageSummary::class);
		$manage->method('forUser')->willReturn(['devices' => 1, 'networks' => 0, 'otherBrowsers' => 2]);
		$stale = $this->createMock(StaleCredentials::class);
		$stale->method('forUser')->willReturn([['id' => 7, 'name' => 'Thunderbird', 'kind' => 'app_password', 'lastUsed' => 1000]]);
		return new Personal($this->settings, $this->overview, $session, $this->state, $this->createMock(IL10N::class), $manage, $stale);
	}
}
