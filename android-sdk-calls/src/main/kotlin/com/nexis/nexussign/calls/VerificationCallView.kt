package com.nexis.nexussign.calls

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.util.AttributeSet
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.nexis.nexussign.CallEndReason
import com.nexis.nexussign.CallState
import com.nexis.nexussign.CaptureState
import com.nexis.nexussign.VerificationChannel
import kotlinx.coroutines.launch
import org.webrtc.RendererCommon
import org.webrtc.SurfaceViewRenderer

/**
 * Call screen: the operator's video (VIDEO), the customer's own camera
 * preview, the transaction terms from the signed bytes, an always-visible
 * camera/microphone indicator, and mute / camera / hang-up buttons.
 *
 * Texts are English defaults; pass [Labels] to localize.
 */
class VerificationCallView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : FrameLayout(context, attrs) {
    data class Labels(
        val waiting: String = "Waiting for a bank employee…",
        val connecting: String = "Connecting…",
        val connected: String = "Connected",
        val reconnecting: String = "Reconnecting…",
        val ended: String = "Call ended",
        val cameraAndMicrophoneOn: String = "Camera and microphone on",
        val microphoneOn: String = "Microphone on",
        val cameraOn: String = "Camera on",
        val off: String = "Camera and microphone off",
        val mute: String = "Mute",
        val unmute: String = "Unmute",
        val cameraOff: String = "Camera off",
        val cameraOnButton: String = "Camera on",
        val hangUp: String = "Hang up",
        val notice: String = "The bank employee checks this payment with you. The call is not recorded. You confirm the payment yourself afterwards.",
        /** Shown before the six-digit call code (finding A2-11). */
        val callCode: String = "Call code",
        val callCodeNotice: String = "The bank employee reads this code to you. If it is different, hang up.",
    )

    private val remote = SurfaceViewRenderer(context)
    private val local = SurfaceViewRenderer(context)
    private val status = TextView(context)
    private val indicator = TextView(context)
    private val terms = TextView(context)
    private val notice = TextView(context)
    private val code = TextView(context)
    private val muteButton = Button(context)
    private val cameraButton = Button(context)
    private val hangUpButton = Button(context)
    private var labels = Labels()
    private var microphoneEnabled = true
    private var cameraEnabled = true
    private var renderersInitialized = false

    init {
        setBackgroundColor(Color.BLACK)
        addView(remote, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT))
        addView(local, LayoutParams(dp(110), dp(150), Gravity.END or Gravity.BOTTOM).apply { setMargins(0, 0, dp(16), dp(96)) })
        val top = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(12))
            setBackgroundColor(Color.argb(170, 0, 0, 0))
            addView(indicator); addView(status); addView(terms); addView(code); addView(notice)
        }
        addView(top, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT, Gravity.TOP))
        indicator.setTextColor(Color.WHITE)
        indicator.textSize = 15f
        indicator.compoundDrawablePadding = dp(8)
        indicator.setCompoundDrawablesRelativeWithIntrinsicBounds(GradientDrawable().apply { shape = GradientDrawable.OVAL; setColor(Color.rgb(229, 57, 53)); setSize(dp(12), dp(12)) }, null, null, null)
        status.setTextColor(Color.LTGRAY)
        terms.setTextColor(Color.WHITE)
        terms.textSize = 18f
        terms.setPadding(0, dp(8), 0, dp(4))
        notice.setTextColor(Color.LTGRAY)
        notice.textSize = 12f
        code.setTextColor(Color.WHITE)
        code.textSize = 22f
        code.typeface = android.graphics.Typeface.MONOSPACE
        code.visibility = View.GONE
        val buttons = LinearLayout(context).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(8), dp(8), dp(8), dp(16))
            addView(muteButton); addView(cameraButton); addView(hangUpButton)
        }
        hangUpButton.setBackgroundColor(Color.rgb(198, 40, 40))
        hangUpButton.setTextColor(Color.WHITE)
        addView(buttons, LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.WRAP_CONTENT, Gravity.BOTTOM))
    }

    /**
     * Binds the view to a call. [termsText] is
     * `authorization.signedTransaction().confirmationText()`: the terms from
     * the signed bytes, the same the operator sees.
     */
    fun bind(owner: LifecycleOwner, call: VerificationCallSession, termsText: String, labels: Labels = Labels()) {
        this.labels = labels
        val video = call.channel == VerificationChannel.VIDEO
        terms.text = termsText
        notice.text = labels.notice
        if (video && !renderersInitialized) {
            remote.init(call.engine.eglBase.eglBaseContext, null)
            remote.setScalingType(RendererCommon.ScalingType.SCALE_ASPECT_FIT)
            local.init(call.engine.eglBase.eglBaseContext, null)
            local.setMirror(true)
            local.setZOrderMediaOverlay(true)
            renderersInitialized = true
            call.engine.remoteSink = remote
            call.engine.localSink = local
        }
        remote.visibility = if (video) View.VISIBLE else View.GONE
        local.visibility = if (video) View.VISIBLE else View.GONE
        cameraButton.visibility = if (video) View.VISIBLE else View.GONE
        muteButton.text = labels.mute
        cameraButton.text = labels.cameraOff
        hangUpButton.text = labels.hangUp
        muteButton.setOnClickListener {
            microphoneEnabled = !microphoneEnabled
            call.setMicrophoneEnabled(microphoneEnabled)
            muteButton.text = if (microphoneEnabled) labels.mute else labels.unmute
        }
        cameraButton.setOnClickListener {
            cameraEnabled = !cameraEnabled
            call.setCameraEnabled(cameraEnabled)
            cameraButton.text = if (cameraEnabled) labels.cameraOff else labels.cameraOnButton
        }
        hangUpButton.setOnClickListener { call.hangUp() }
        owner.lifecycleScope.launch { call.controller.capture.collect(::showCapture) }
        owner.lifecycleScope.launch {
            call.controller.callCode.collect { value ->
                code.visibility = if (value == null) View.GONE else View.VISIBLE
                if (value != null) {
                    code.text = "${labels.callCode} ${value.take(3)} ${value.takeLast(3)}"
                    notice.text = "${labels.callCodeNotice}\n${labels.notice}"
                }
            }
        }
        owner.lifecycleScope.launch {
            call.controller.state.collect { state ->
                status.text = statusText(state)
                if (state is CallState.Ended) {
                    muteButton.isEnabled = false; cameraButton.isEnabled = false; hangUpButton.isEnabled = false
                    call.engine.localSink = null; call.engine.remoteSink = null
                }
            }
        }
    }

    /** Release the renderers when the screen goes away (after the call ended). */
    fun release() {
        if (renderersInitialized) { remote.release(); local.release(); renderersInitialized = false }
    }

    private fun showCapture(capture: CaptureState) {
        indicator.text = when {
            capture.cameraOn && capture.microphoneOn -> labels.cameraAndMicrophoneOn
            capture.microphoneOn -> labels.microphoneOn
            capture.cameraOn -> labels.cameraOn
            else -> labels.off
        }
        // The red dot shows whenever anything captures.
        indicator.compoundDrawablesRelative[0]?.alpha = if (capture.cameraOn || capture.microphoneOn) 255 else 0
    }

    private fun statusText(state: CallState): String = when (state) {
        CallState.Idle, CallState.Joining, CallState.WaitingForOperator -> labels.waiting
        CallState.Connecting -> labels.connecting
        CallState.Connected -> labels.connected
        is CallState.Reconnecting -> labels.reconnecting
        is CallState.Ended -> when (val r = state.reason) {
            is CallEndReason.Decided -> labels.ended
            else -> "${labels.ended} (${r.javaClass.simpleName})"
        }
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
