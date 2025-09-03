/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.os.Build
import io.github.beakthoven.TrickyStoreOSS.config.PkgConfig
import io.github.beakthoven.TrickyStoreOSS.interceptors.Keystore2Interceptor
import io.github.beakthoven.TrickyStoreOSS.interceptors.KeystoreInterceptor
import io.github.beakthoven.TrickyStoreOSS.logging.Logger

private const val RETRY_DELAY_MS = 1000L
private const val SERVICE_SLEEP_MS = 1000000L

fun main(args: Array<String>) {
    Logger.i("Welcome to TrickyStoreOSS!")
    
    try {
        AndroidUtils.setupBootHash()
        initializeInterceptors()
        maintainService()
    } catch (e: Exception) {
        Logger.e("Fatal error in main", e)
        throw e
    }
}

private fun initializeInterceptors() {
    val interceptor = selectKeystoreInterceptor()
    
    while (!interceptor.tryRunKeystoreInterceptor()) {
        Logger.d("Retrying interceptor initialization...")
        Thread.sleep(RETRY_DELAY_MS)
    }
    
    PkgConfig.initialize()
    clearKeyStore()
    Logger.i("Interceptors initialized successfully")
}

private fun clearKeyStore() {
    val targetUIDs = PkgConfig.getKSClearPackageUids()
    Logger.i("Clearing keystore for ${targetUIDs.size} target packages")

    targetUIDs.forEach { uid ->
        kotlin.runCatching {
            android.security.AndroidKeyStoreMaintenance.clearNamespace(0, uid.toLong())
            Logger.d("Cleared keystore namespace for UID: $uid")
        }.onFailure {
            Logger.e("Failed to clear keystore for UID: $uid", it)
        }
    }
}

private fun selectKeystoreInterceptor() = when {
    Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
        Logger.i("Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})")
        KeystoreInterceptor
    }
    else -> {
        Logger.i("Using Keystore2Interceptor for Android S+ (SDK ${Build.VERSION.SDK_INT})")
        Keystore2Interceptor
    }
}

private fun maintainService() {
    Logger.i("Service started, entering maintenance mode")
    while (true) {
        Thread.sleep(SERVICE_SLEEP_MS)
    }
}
