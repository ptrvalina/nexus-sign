package com.nexis.nexussign.calls

import android.content.Context
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.nexis.nexussign.NEXUSSignError
import com.nexis.nexussign.NEXUSSignSDK
import com.nexis.nexussign.NexusAuthorization
import com.nexis.nexussign.VerificationCallController
import com.nexis.nexussign.VerificationChannel
import com.nexis.nexussign.VerificationSession
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * One verification call of the customer, from opening the session to the
 * end: NEXUS-SIGN SDK session and signalling, the libwebrtc engine, the call
 * state machine, and the activity lifecycle.
 *
 * Lifecycle rules:
 *  - in the background (onStop) the camera is stopped; it starts again in
 *    onStart unless the customer turned it off. Android does not allow
 *    background camera use anyway; the microphone stays on while the
 *    activity exists;
 *  - when the owner is destroyed for good (not a configuration change), the
 *    call is hung up and media released;
 *  - a call that has ended releases camera and microphone immediately.
 *
 * Usage (after CallPermissions are granted):
 * ```
 * val call = VerificationCallSession.open(sdk, context, authorization, VerificationChannel.VIDEO)
 * callView.bind(this, call, authorization.signedTransaction().confirmationText())
 * call.start(this)
 * ```
 */
class VerificationCallSession private constructor(
    val session: VerificationSession,
    val engine: WebRtcCallEngine,
    val controller: VerificationCallController,
    private val scope: CoroutineScope,
) {
    private var cameraWantedOn = true
    private var stoppedByLifecycle = false

    val channel: VerificationChannel get() = session.channel

    fun start(owner: LifecycleOwner) {
        owner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStop(owner: LifecycleOwner) {
                if (channel == VerificationChannel.VIDEO && cameraWantedOn && !controller.isEnded) {
                    controller.setCameraEnabled(false)
                    stoppedByLifecycle = true
                }
            }
            override fun onStart(owner: LifecycleOwner) {
                if (stoppedByLifecycle && !controller.isEnded) controller.setCameraEnabled(true)
                stoppedByLifecycle = false
            }
            override fun onDestroy(owner: LifecycleOwner) {
                val changingConfigurations = (owner as? android.app.Activity)?.isChangingConfigurations == true
                if (!changingConfigurations) hangUp()
            }
        })
        controller.start()
    }

    fun setCameraEnabled(enabled: Boolean) { cameraWantedOn = enabled; controller.setCameraEnabled(enabled) }
    fun setMicrophoneEnabled(enabled: Boolean) = controller.setMicrophoneEnabled(enabled)

    /** Ends or declines the call; nothing is verified or failed. */
    fun hangUp() {
        // Outlives the activity: the cancel should reach Auth Core.
        scope.launch {
            try { controller.hangUp() } finally { scope.cancel() }
        }
    }

    companion object {
        /**
         * Opens the session (Auth Core binds it to [authorization] and this
         * device) and prepares the call. Throws [NEXUSSignError] for a
         * session Auth Core refuses (channel not offered, attempts used up,
         * authorization no longer pending).
         */
        suspend fun open(
            sdk: NEXUSSignSDK,
            context: Context,
            authorization: NexusAuthorization,
            channel: VerificationChannel,
            options: VerificationCallController.Options = VerificationCallController.Options(),
        ): VerificationCallSession {
            val missing = CallPermissions.missing(context, channel)
            require(missing.isEmpty()) { "Permissions not granted: $missing" }
            val session = sdk.openVerificationCall(authorization, channel)
            val engine = WebRtcCallEngine(context)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
            val controller = VerificationCallController(sdk.callSignalling(session), engine, scope, options)
            return VerificationCallSession(session, engine, controller, scope)
        }
    }
}
