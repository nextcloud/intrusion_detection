/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { addPasswordConfirmationInterceptors } from '@nextcloud/password-confirmation'
import { createApp } from 'vue'
import PersonalSettings from './views/PersonalSettings.vue'
import { initPersonalState } from './personal/store.ts'

import 'vite/modulepreload-polyfill'

addPasswordConfirmationInterceptors(axios)
initPersonalState()

createApp(PersonalSettings).mount('#intrusion-detection')
