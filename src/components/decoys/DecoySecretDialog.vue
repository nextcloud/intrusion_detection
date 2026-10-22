<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { NewDecoy } from '../../types.ts'

import { mdiAlertOutline, mdiCheck, mdiContentCopy, mdiFileDocumentOutline, mdiFolderNetworkOutline, mdiNoteTextOutline, mdiScriptTextOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { useCopy } from '../../composables/useCopy.ts'
import { APP_ID } from '../../utils/format.ts'

/**
 * The secret of a new decoy, shown this once. The parent hands it over and
 * forgets it; this dialog drops it when it closes.
 */
const created = defineModel<NewDecoy | null>('created', { required: true })

const stored = ref(false)
const { copied, copy } = useCopy()

watch(created, (value) => {
	if (value !== null) {
		stored.value = false
	}
})

const open = computed({
	get: () => created.value !== null,
	set: (value: boolean) => {
		if (!value && stored.value) {
			created.value = null
		}
	},
})

const IDEAS = [
	{ icon: mdiScriptTextOutline, text: () => t(APP_ID, 'An old script on a file server, for example a backup job that "logs in" to Nextcloud.') },
	{ icon: mdiFileDocumentOutline, text: () => t(APP_ID, 'A wiki or intranet page about backups or migrations.') },
	{ icon: mdiFolderNetworkOutline, text: () => t(APP_ID, 'A configuration file on a shared drive or in a repository that only staff can read.') },
	{ icon: mdiNoteTextOutline, text: () => t(APP_ID, 'A note in a password manager export, or an email draft in a mailbox.') },
]

const buttons = computed(() => [
	{ label: t(APP_ID, 'Done'), variant: 'primary' as const, disabled: !stored.value, callback: () => { created.value = null } },
])

/**
 * Copy the secret.
 */
async function copySecret() {
	if (created.value && await copy(created.value.secret, t(APP_ID, 'The secret was copied.'))) {
		stored.value = true
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Your decoy credential')"
		:buttons="buttons"
		:noClose="!stored"
		size="normal">
		<div v-if="created" :class="$style.secret">
			<p :class="$style.secret__warning" role="note">
				<NcIconSvgWrapper inline :path="mdiAlertOutline" :size="20" />
				<span>{{ t(APP_ID, 'This is the only time the secret is shown. Nextcloud keeps only a fingerprint of it, so it cannot show it again. Copy it now.') }}</span>
			</p>

			<div :class="$style.secret__box">
				<span :class="$style.secret__label">{{ created.decoy.label }}</span>
				<code :class="$style.secret__value" data-test="decoy-secret">{{ created.secret }}</code>
				<div :class="$style.secret__actions">
					<NcButton variant="primary" data-test="copy-secret" @click="copySecret">
						<template #icon>
							<NcIconSvgWrapper :path="copied ? mdiCheck : mdiContentCopy" />
						</template>
						{{ copied ? t(APP_ID, 'Copied') : t(APP_ID, 'Copy secret') }}
					</NcButton>
					<span v-if="created.decoy.loginName" :class="$style.secret__login">
						{{ t(APP_ID, 'Login name:') }} <code>{{ created.decoy.loginName }}</code>
					</span>
				</div>
			</div>

			<div>
				<h3 :class="$style.secret__heading">
					{{ t(APP_ID, 'Where to plant it') }}
				</h3>
				<p :class="$style.secret__text">
					{{ t(APP_ID, 'Put it where only someone who broke in would find it, and where no colleague would ever use it. Anyone who tries it has found it there, and is blocked at once.') }}
				</p>
				<ul :class="$style.ideas">
					<li v-for="(idea, index) in IDEAS" :key="index">
						<NcIconSvgWrapper inline :path="idea.icon" :size="20" />
						<span>{{ idea.text() }}</span>
					</li>
				</ul>
			</div>

			<NcCheckboxRadioSwitch v-model="stored" data-test="secret-stored">
				{{ t(APP_ID, 'I have copied the secret') }}
			</NcCheckboxRadioSwitch>
		</div>
	</NcDialog>
</template>

<style module>
.secret {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	padding-bottom: var(--ids-space-2);
}

.secret__warning {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	margin: 0;
	padding: var(--ids-space-3);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-warning) 14%, var(--color-main-background));
	line-height: 1.5;
}

.secret__warning > :first-child {
	flex: 0 0 auto;
	color: var(--color-warning-text);
}

.secret__box {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	padding: var(--ids-space-4);
	border: 1px dashed var(--color-border-dark, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.secret__label {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.9em;
}

.secret__value {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 1.25em;
	font-weight: 600;
	letter-spacing: 0.03em;
	overflow-wrap: anywhere;
	user-select: all;
}

.secret__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-3);
}

.secret__login {
	composes: muted from '../../styles/shared.module.css';
}

.secret__login code {
	color: var(--color-main-text);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.secret__heading {
	margin: 0 0 var(--ids-space-1);
	font-size: 1em;
	font-weight: 700;
}

.secret__text {
	margin: 0 0 var(--ids-space-2);
	line-height: 1.5;
}

.ideas {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.ideas li {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	line-height: 1.45;
}

.ideas li > :first-child {
	flex: 0 0 auto;
	color: var(--color-primary-element);
}
</style>
