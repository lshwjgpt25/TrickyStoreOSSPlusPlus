/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package io.github.beakthoven.TrickyStoreOSS

import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import android.util.Log
import io.github.beakthoven.TrickyStoreOSS.CertificateUtils.putCertificateChain
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

object CertificateUtils {
    private const val TAG = "TrickyStoreOSS"
    
    sealed class CertificateResult<out T> {
        data class Success<T>(val data: T) : CertificateResult<T>()
        data class Error(val message: String, val cause: Throwable? = null) : CertificateResult<Nothing>()
        
        inline fun <R> map(transform: (T) -> R): CertificateResult<R> = when (this) {
            is Success -> Success(transform(data))
            is Error -> this
        }
        
        fun getOrNull(): T? = when (this) {
            is Success -> data
            is Error -> null
        }
    }
    
    fun ByteArray?.toCertificate(): X509Certificate? {
        return this?.let { bytes ->
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificate(ByteArrayInputStream(bytes)) as? X509Certificate
            } catch (e: CertificateException) {
                Log.w(TAG, "Couldn't parse certificate in keystore", e)
                null
            }
        }
    }
    
    fun ByteArray.toCertificateResult(): CertificateResult<X509Certificate> {
        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certificate = certFactory.generateCertificate(ByteArrayInputStream(this)) as X509Certificate
            CertificateResult.Success(certificate)
        } catch (e: CertificateException) {
            CertificateResult.Error("Failed to parse certificate", e)
        }
    }
    
    @Suppress("UNCHECKED_CAST")
    fun ByteArray?.toCertificates(): Collection<X509Certificate> {
        return this?.let { bytes ->
            try {
                val certFactory = CertificateFactory.getInstance("X.509")
                certFactory.generateCertificates(ByteArrayInputStream(bytes)) as Collection<X509Certificate>
            } catch (e: CertificateException) {
                Log.w(TAG, "Couldn't parse certificates in keystore", e)
                emptyList()
            }
        } ?: emptyList()
    }
    
    fun Collection<Certificate>.toByteArray(): ByteArray? = runCatching {
        ByteArrayOutputStream().use { outputStream ->
            forEach { cert -> outputStream.write(cert.encoded) }
            outputStream.toByteArray()
        }
    }.onFailure { 
        Log.w(TAG, "Failed to convert certificates to byte array", it) 
    }.getOrNull()
    
    fun Collection<Certificate>.toByteArrayList(): List<ByteArray>? = runCatching {
        map { it.encoded }
    }.onFailure { 
        Log.w(TAG, "Failed to convert certificates to byte array list", it) 
    }.getOrNull()
    
    fun KeyEntryResponse?.getCertificateChain(): Array<Certificate>? {
        val metadata = this?.metadata ?: return null
        val leafCert = metadata.certificate?.toCertificate() ?: return null
        
        return when (val chainBytes = metadata.certificateChain) {
            null -> arrayOf(leafCert)
            else -> {
                val additionalCerts = chainBytes.toCertificates()
                buildList {
                    add(leafCert)
                    addAll(additionalCerts)
                }.toTypedArray()
            }
        }
    }
    
    fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
        return runCatching {
            metadata.putCertificateChain(chain)
        }
    }
    
    fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
        return runCatching {
            if (chain.isEmpty()) return@runCatching
            
            certificate = chain[0].encoded
            
            if (chain.size > 1) {
                ByteArrayOutputStream().use { output ->
                    for (i in 1 until chain.size) {
                        output.write(chain[i].encoded)
                    }
                    certificateChain = output.toByteArray()
                }
            } else {
                certificateChain = null
            }
        }
    }
}

fun ByteArray?.toX509Certificate(): X509Certificate? = CertificateUtils.run { this@toX509Certificate.toCertificate() }

fun ByteArray?.toX509Certificates(): Collection<X509Certificate> = CertificateUtils.run { this@toX509Certificates.toCertificates() }

fun Collection<Certificate>.encodedBytes(): ByteArray? = CertificateUtils.run { this@encodedBytes.toByteArray() }

fun Collection<Certificate>.encodedBytesList(): List<ByteArray>? = CertificateUtils.run { this@encodedBytesList.toByteArrayList() }

fun KeyEntryResponse.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching {
        metadata.putCertificateChain(chain).getOrThrow()
    }
}

fun KeyMetadata.putCertificateChain(chain: Array<Certificate>): Result<Unit> {
    return runCatching {
        if (chain.isEmpty()) return@runCatching
        
        certificate = chain[0].encoded
        
        if (chain.size > 1) {
            ByteArrayOutputStream().use { output ->
                for (i in 1 until chain.size) {
                    output.write(chain[i].encoded)
                }
                certificateChain = output.toByteArray()
            }
        } else {
            certificateChain = null
        }
    }
}