<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @var \OCP\IL10N $l */
/** @var array{events: list<array{id: int, subject: string, when: string, happened: list<string>, done: list<string>, asks: bool, verdict: ?string, canConfirm: bool, denyAction: string, confirmAction: string}>, error: ?string, notice: ?string, redirect_url: string, continueAction: string, logout_url: string, requesttoken: string} $_ */
$events = $_['events'];
?>
<div class="guest-box ids-page ids-page--wide">
	<div class="ids-page__icon ids-page__icon--notice" aria-hidden="true"></div>
	<h2 class="ids-page__title"><?php p($l->t('Security notice for your account')); ?></h2>
	<p class="ids-page__lead"><?php p($l->t('Nextcloud noticed something about your account while you were away, and could not reach you by email. Please read it before you continue.')); ?></p>

	<?php if ($_['error'] !== null): ?>
		<p class="ids-page__error" role="alert"><?php p($_['error']); ?></p>
	<?php elseif ($_['notice'] !== null): ?>
		<p class="ids-page__notice" role="status"><?php p($_['notice']); ?></p>
	<?php endif; ?>

	<?php if ($events === []): ?>
		<p class="ids-page__hint"><?php p($l->t('The events were removed in the meantime. Nothing needs your attention.')); ?></p>
	<?php else: ?>
		<ul class="ids-page__events">
			<?php foreach ($events as $event): ?>
				<li class="ids-page__event">
					<h3 class="ids-page__event-title"><?php p($event['subject']); ?></h3>
					<p class="ids-page__meta"><?php p($event['when']); ?></p>
					<?php foreach ($event['happened'] as $sentence): ?>
						<p class="ids-page__event-text"><?php p($sentence); ?></p>
					<?php endforeach; ?>
					<?php if ($event['asks'] && $event['verdict'] === null): ?>
						<p class="ids-page__event-question"><?php p($l->t('Was this you?')); ?></p>
						<div class="ids-page__event-actions">
							<form method="post" action="<?php p($event['confirmAction']); ?>">
								<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
								<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">
								<button class="ids-page__secondary" type="submit"><?php p($l->t('Yes, it was me')); ?></button>
							</form>
							<form method="post" action="<?php p($event['denyAction']); ?>">
								<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
								<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">
								<button class="ids-page__secondary ids-page__danger" type="submit"><?php p($l->t('No, it was not me')); ?></button>
							</form>
						</div>
						<?php if (!$event['canConfirm']): ?>
							<p class="ids-page__hint"><?php p($l->t('"Yes" needs a login with your second factor, a confirmed login, or a remembered device. From this login only "No" can be taken; answer "Yes" later from such a login.')); ?></p>
						<?php endif; ?>
					<?php elseif ($event['verdict'] !== null): ?>
						<p class="ids-page__answered"><?php p($event['verdict'] === 'denied' ? $l->t('You answered: No, it was not me.') : $l->t('You answered: Yes, it was me.')); ?></p>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php endif; ?>

	<p class="ids-page__hint"><?php p($l->t('Add an email address in your personal settings, so Nextcloud can reach you if this happens again.')); ?></p>

	<form class="ids-page__form" method="post" action="<?php p($_['continueAction']); ?>">
		<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
		<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">
		<button class="primary ids-page__submit" type="submit"><?php p($l->t('Continue to Nextcloud')); ?></button>
	</form>

	<div class="ids-page__actions">
		<a href="<?php p($_['logout_url']); ?>"><?php p($l->t('Log out')); ?></a>
	</div>
</div>
