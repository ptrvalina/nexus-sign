package com.nexis.nexussign.calls

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import com.nexis.nexussign.VerificationChannel

/**
 * Run-time permissions a call needs. The bank app asks for them (for example
 * with ActivityResultContracts.RequestMultiplePermissions) right before the
 * customer starts the call, never earlier; an AUDIO call never asks for the
 * camera.
 */
object CallPermissions {
    fun required(channel: VerificationChannel): Array<String> = when (channel) {
        VerificationChannel.AUDIO -> arrayOf(Manifest.permission.RECORD_AUDIO)
        VerificationChannel.VIDEO -> arrayOf(Manifest.permission.RECORD_AUDIO, Manifest.permission.CAMERA)
    }

    fun missing(context: Context, channel: VerificationChannel): List<String> =
        required(channel).filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
}
