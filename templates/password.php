<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @var \OCP\IL10N $l */
/** @var array{action: string, redirect_url: string, logout_url: string, error: ?string, requesttoken: string} $_ */
$error = $_['error'];
?>
<div class="guest-box ids-page">
	<div class="ids-page__icon" aria-hidden="true"></div>
	<h2 class="ids-page__title"><?php p($l->t('Choose a new password')); ?></h2>
	<p class="ids-page__lead">
		<?php p($l->t('Nextcloud noticed something unusual around your account. To keep it safe, choose a new password before you continue.')); ?>
	</p>
	<p class="ids-page__hint">
		<?php p($l->t('Someone else may know your current password. Use a new one that you do not use anywhere else. Apps and devices connected with an app password keep working.')); ?>
	</p>

	<?php if ($error !== null): ?>
		<p class="ids-page__error" id="ids-page-error" role="alert">
			<?php p($error); ?>
		</p>
	<?php endif; ?>

	<form class="ids-page__form" method="post" action="<?php p($_['action']); ?>">
		<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
		<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">

		<label class="ids-page__label" for="ids-page-current"><?php p($l->t('Current password')); ?></label>
		<input class="ids-page__input" id="ids-page-current" type="password" name="currentPassword"
			autocomplete="current-password" required autofocus
			<?php if ($error !== null): ?>aria-describedby="ids-page-error"<?php endif; ?>>

		<label class="ids-page__label" for="ids-page-new"><?php p($l->t('New password')); ?></label>
		<input class="ids-page__input" id="ids-page-new" type="password" name="newPassword"
			autocomplete="new-password" required maxlength="469"
			<?php if ($error !== null): ?>aria-describedby="ids-page-error"<?php endif; ?>>

		<label class="ids-page__label" for="ids-page-repeat"><?php p($l->t('Repeat the new password')); ?></label>
		<input class="ids-page__input" id="ids-page-repeat" type="password" name="newPasswordRepeat"
			autocomplete="new-password" required maxlength="469">

		<div class="ids-page__remember">
			<input id="ids-page-logout-others" type="checkbox" name="logoutOthers" value="1" checked>
			<label for="ids-page-logout-others"><?php p($l->t('Log out on all other browsers')); ?></label>
		</div>

		<button class="primary ids-page__submit" type="submit"><?php p($l->t('Change password and continue')); ?></button>
	</form>

	<div class="ids-page__actions">
		<a href="<?php p($_['logout_url']); ?>"><?php p($l->t('Log out')); ?></a>
	</div>
</div>
