import api from '@main/api'
import { useEmitter } from '@main/composables/useEmitter'
import { usePushNotifications } from '@main/composables/usePushNotifications'
import { EMITTER_EVENTS } from '@main/constants/emitterEvents.js'
import { clearNewConversationDrafts } from '@main/features/conversation/useNewConversationDraft.js'
import { handleHTTPError } from '@shared-ui/utils/http.js'
import { useAppSettingsStore } from '@main/stores/appSettings'
import { GUARD_LOGOUT_PATH, guardIdentityEnabled } from '@main/utils/guard-auth.js'

const defaultBrowser = typeof window === 'undefined' ? {} : window

export const createLogout = (pushNotifications, browser = defaultBrowser, apiClient = api, redirectTo = '/') => async () => {
  await Promise.resolve(pushNotifications.disable()).catch(() => {})
  try {
    await apiClient.logout()
  } catch (error) {
    if (error?.response?.status !== 401) throw error
  }
  clearNewConversationDrafts(browser.localStorage)
  browser.location.href = redirectTo
}

export const useLogout = () => {
  const emitter = useEmitter()
  // metsa: with guard's identity, signing out ends guard's session.
  const guard = guardIdentityEnabled(useAppSettingsStore().public_config)
  const logout = createLogout(
    usePushNotifications(),
    defaultBrowser,
    api,
    guard ? GUARD_LOGOUT_PATH : '/'
  )
  return async () => {
    try {
      await logout()
    } catch (error) {
      emitter.emit(EMITTER_EVENTS.SHOW_TOAST, {
        variant: 'destructive',
        description: handleHTTPError(error).message
      })
    }
  }
}
