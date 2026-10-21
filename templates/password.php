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
<div class="guest-box ids-password">
	<div class="ids-password__icon" aria-hidden="true"></div>
	<h2 class="ids-password__title"><?php p($l->t('Choose a new password')); ?></h2>
	<p class="ids-password__lead">
		<?php p($l->t('Nextcloud noticed something unusual around your account. To keep it safe, choose a new password before you continue.')); ?>
	</p>
	<p class="ids-password__hint">
		<?php p($l->t('Someone else may know your current password. Use a new one that you do not use anywhere else. Apps and devices connected with an app password keep working.')); ?>
	</p>

	<?php if ($error !== null): ?>
		<p class="ids-password__error" id="ids-password-error" role="alert">
			<?php p($error); ?>
		</p>
	<?php endif; ?>

	<form class="ids-password__form" method="post" action="<?php p($_['action']); ?>">
		<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
		<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url']); ?>">

		<label class="ids-password__label" for="ids-password-current"><?php p($l->t('Current password')); ?></label>
		<input class="ids-password__input" id="ids-password-current" type="password" name="currentPassword"
			autocomplete="current-password" required autofocus
			<?php if ($error !== null): ?>aria-describedby="ids-password-error"<?php endif; ?>>

		<label class="ids-password__label" for="ids-password-new"><?php p($l->t('New password')); ?></label>
		<input class="ids-password__input" id="ids-password-new" type="password" name="newPassword"
			autocomplete="new-password" required maxlength="469"
			<?php if ($error !== null): ?>aria-describedby="ids-password-error"<?php endif; ?>>

		<label class="ids-password__label" for="ids-password-repeat"><?php p($l->t('Repeat the new password')); ?></label>
		<input class="ids-password__input" id="ids-password-repeat" type="password" name="newPasswordRepeat"
			autocomplete="new-password" required maxlength="469">

		<button class="primary ids-password__submit" type="submit"><?php p($l->t('Change password and continue')); ?></button>
	</form>

	<div class="ids-password__actions">
		<a href="<?php p($_['logout_url']); ?>"><?php p($l->t('Log out')); ?></a>
	</div>
</div>
