<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '@nextcloud/l10n'
import { APP_ID } from '../../utils/format.ts'

// The card passes the check as `check`; this section does not need it, and it must not end up as an attribute.
defineOptions({ inheritAttrs: false })

/** The service's explanation of the range search: only a hash prefix is sent (k-anonymity) */
const K_ANONYMITY_URL = 'https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange'
</script>

<template>
	<p :class="$style.privacy" data-test="breach-privacy">
		<a :href="K_ANONYMITY_URL" target="_blank" rel="noreferrer noopener">
			{{ t(APP_ID, 'How sending 5 characters of the hash keeps the password secret (k-anonymity)') }}
		</a>
	</p>
</template>

<style module>
.privacy a {
	color: var(--color-main-text);
	text-decoration: underline;
}
</style>
