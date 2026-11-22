package com.nexis.nexussign.demo

import android.graphics.Typeface
import android.os.Bundle
import android.view.View
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.nexis.nexussign.NEXUSSignConfig
import com.nexis.nexussign.NEXUSSignError
import com.nexis.nexussign.NEXUSSignSDK
import com.nexis.nexussign.NEXUSVerificationOutcome
import com.nexis.nexussign.NexusAuthorization
import com.nexis.nexussign.CallEndReason
import com.nexis.nexussign.CallState
import com.nexis.nexussign.VerificationChannel
import com.nexis.nexussign.calls.CallPermissions
import com.nexis.nexussign.calls.VerificationCallSession
import com.nexis.nexussign.calls.VerificationCallView
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Demo host app: enrols this phone with Auth Core, shows the payment the
 * demo bank sends, and signs it after the biometric prompt. The keys are
 * created by the SDK in the Android Keystore (StrongBox when present).
 *
 * Auth Core and the demo bank run on the computer; `adb reverse` makes the
 * demo bank's device port reachable on the phone at 127.0.0.1:8091.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var sdk: NEXUSSignSDK
    // Read by DemoBank on an I/O thread, so it is copied out of the view.
    @Volatile private var pairingCode = ""
    private val bank = DemoBank(DEMO_BANK_URL) { pairingCode }

    private lateinit var pairingField: EditText

    private lateinit var registerButton: Button
    private lateinit var paymentCard: LinearLayout
    private lateinit var paymentText: TextView
    private lateinit var approveButton: Button
    private lateinit var callButton: Button
    private lateinit var recoveryButton: Button
    private lateinit var offlineQrButton: Button
    private lateinit var offlineCodeButton: Button
    private lateinit var offlineCodeView: TextView
    // Offline confirmation: the QR content fetched while online.
    private var offlineQr: String? = null
    private lateinit var statusView: TextView

    private var current: NexusAuthorization? = null
    private var busy = false
    // The call the bank's policy asks for before signing (ADR 0017), and
    // whether the operator has recorded VERIFIED for it.
    private var requiredCall: VerificationChannel? = null
    private var callVerified = false
    private lateinit var mainUi: View
    private val permissionRequest = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        if (granted.values.all { it }) startCall() else setStatus("Без доступа к микрофону (и камере для видео) звонок невозможен.")
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        sdk = NEXUSSignSDK(
            this,
            NEXUSSignConfig(
                bankId = "local-bank",
                baseUrl = AUTH_CORE_URL,
                sessionTokenProvider = { _ -> bank.bootstrapToken() },
                promptTitle = "Подтвердите платёж",
                promptCancelText = "Отмена",
                recoverySetupPromptText = "Подтвердите новую фразу восстановления",
            ),
        )
        mainUi = buildUi()
        setContentView(mainUi)
        setStatus(
            if (sdk.isRegistered()) "Телефон зарегистрирован. Ожидаю платёж от банка…"
            else "Нажмите «Зарегистрировать телефон». Ключи будут созданы в аппаратном хранилище этого телефона.",
        )
        render()
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    poll()
                    delay(POLL_INTERVAL_MILLIS)
                }
            }
        }
    }

    /** Asks the demo bank whether a payment is waiting, and loads it through the SDK. */
    private suspend fun poll() {
        if (busy || !sdk.isRegistered()) return
        // Offline confirmations: signatures made without network go out as soon as there is one.
        // Every outcome is shown: a refused signature never confirms the payment.
        val delivery = runCatching { sdk.submitPendingOfflineSignatures() }.getOrNull()
        if (delivery != null && delivery.delivered > 0) {
            offlineCodeView.visibility = View.GONE
            setStatus("Подпись офлайн-подтверждения принята Auth Core (${delivery.delivered}). Итог — на странице демо-банка.")
        }
        if (delivery != null && delivery.refused > 0) {
            offlineCodeView.visibility = View.GONE
            setStatus("Auth Core не принял подпись офлайн-подтверждения (${delivery.refused}). Платёж этой подписью не подтвердится: отправьте новый платёж. Причина — в журнале Auth Core (deferred_signature_*).")
        }
        if (delivery != null && delivery.pending > 0 && offlineCodeView.visibility == View.VISIBLE) {
            setStatus("Подпись ждёт отправки (${delivery.pending}): нет связи с сервером. Уйдёт сама, как только появится сеть.")
        }
        if (current != null) return
        val answer = runCatching { bank.pending() }
        answer.exceptionOrNull()?.let { error ->
            // Shown instead of silently waiting, unless an offline code is on screen.
            if (offlineCodeView.visibility != View.VISIBLE) show(error)
            return
        }
        val pending = answer.getOrNull() ?: return
        offlineCodeView.visibility = View.GONE
        try {
            // The SDK checks that every displayed field matches the exact bytes it will sign.
            current = sdk.fetchAuthorization(pending.authorizationId)
            requiredCall = pending.call?.let { VerificationChannel.valueOf(it) }
            callVerified = false
            setStatus(
                if (requiredCall == null) "Банк просит подтвердить платёж. Проверьте сумму и получателя."
                else "Банк просит сначала проверить платёж в звонке с сотрудником, затем подтвердить его биометрией.",
            )
        } catch (e: Exception) {
            show(e)
        }
        render()
    }

    private fun register() {
        lifecycleScope.launch {
            busy = true
            current = null
            render()
            setStatus("Регистрация: создаю ключи в аппаратном хранилище телефона…")
            try {
                val registration = sdk.bootstrap()
                bank.registered(registration.credentialId)
                setStatus(
                    "Телефон зарегистрирован.\n" +
                        "NEXUS ID: ${registration.nexusId}\n" +
                        "Устройство: ${registration.credentialId}\n" +
                        "Аттестация: ${registration.attestationStatus}\n\n" +
                        "Отправьте платёж со страницы демо-банка на компьютере.",
                )
            } catch (e: Exception) {
                show(e)
            } finally {
                busy = false
                render()
            }
        }
    }

    private fun approve() {
        val authorization = current ?: return
        lifecycleScope.launch {
            busy = true
            render()
            try {
                when (sdk.approve(authorization, this@MainActivity)) {
                    NEXUSVerificationOutcome.VERIFIED ->
                        setStatus("Платёж подтверждён подписью устройства. Банк получил доказательство, заверенное в HSM.")
                    NEXUSVerificationOutcome.FAILED -> setStatus("Сервер не принял подпись.")
                    NEXUSVerificationOutcome.EXPIRED -> setStatus("Срок подтверждения истёк.")
                }
            } catch (e: Exception) {
                show(e)
            } finally {
                current = null
                busy = false
                render()
            }
        }
    }

    /** Asks for microphone (and camera) right before the call, then starts it. */
    private fun requestCall() {
        val channel = requiredCall ?: return
        val missing = CallPermissions.missing(this, channel)
        if (missing.isEmpty()) startCall() else permissionRequest.launch(missing.toTypedArray())
    }

    private fun startCall() {
        val authorization = current ?: return
        val channel = requiredCall ?: return
        lifecycleScope.launch {
            busy = true
            render()
            try {
                val call = VerificationCallSession.open(sdk, this@MainActivity, authorization, channel)
                val view = VerificationCallView(this@MainActivity)
                // The terms on the call screen come from the signed bytes.
                view.bind(this@MainActivity, call, authorization.signedTransaction().confirmationText())
                setContentView(view)
                call.start(this@MainActivity)
                val ended = call.controller.state.first { it is CallState.Ended } as CallState.Ended
                delay(1_500)
                view.release()
                setContentView(mainUi)
                when (val reason = ended.reason) {
                    is CallEndReason.Decided -> {
                        callVerified = reason.verified
                        setStatus(if (reason.verified) "Сотрудник подтвердил проверку. Теперь подтвердите платёж биометрией." else "Проверка в звонке не пройдена: банк отклонил платёж.")
                    }
                    CallEndReason.OperatorLeft, CallEndReason.CancelledByCustomer, CallEndReason.Expired, CallEndReason.ConnectionLost ->
                        setStatus("Звонок завершён без результата. Можно позвонить ещё раз (до трёх попыток).")
                    else -> setStatus("Звонок завершён: $reason")
                }
            } catch (e: Exception) {
                setContentView(mainUi)
                show(e)
            } finally {
                busy = false
                render()
            }
        }
    }

    /** Step 1, online: the QR content of the waiting payment. */
    private fun fetchOfflineQr() {
        lifecycleScope.launch {
            busy = true
            render()
            try {
                offlineQr = bank.offlineChallenge()
                offlineCodeView.visibility = View.GONE
                setStatus("QR получен. Отключите сеть (авиарежим и отсоедините USB-кабель), затем нажмите «Показать офлайн-код».")
            } catch (e: Exception) {
                show(e)
            } finally {
                busy = false
                render()
            }
        }
    }

    /**
     * Step 2, without network: the SDK checks the QR, asks for the biometric
     * with the transaction and returns the 8-digit code; the signature waits in
     * the SDK until the phone is online again.
     */
    private fun showOfflineCode() {
        val qr = offlineQr ?: return
        lifecycleScope.launch {
            busy = true
            render()
            try {
                val challenge = sdk.readOfflineChallenge(qr)
                val code = sdk.confirmOffline(challenge, this@MainActivity)
                offlineQr = null
                current = null
                offlineCodeView.text = "${code.take(4)} ${code.takeLast(4)}"
                offlineCodeView.visibility = View.VISIBLE
                setStatus("Введите этот код на странице демо-банка. Затем верните сеть (и кабель с adb reverse): приложение отправит подпись.")
            } catch (e: Exception) {
                show(e)
            } finally {
                busy = false
                render()
            }
        }
    }

    private fun createRecoveryPhrase() {
        lifecycleScope.launch {
            busy = true
            render()
            try {
                val words = sdk.generateRecoveryPhrase(this@MainActivity)
                setStatus(
                    "Фраза восстановления. Запишите её: она не покидает телефон.\n\n" +
                        words.chunked(4).joinToString("\n") { line -> line.joinToString("   ") },
                )
            } catch (e: Exception) {
                show(e)
            } finally {
                busy = false
                render()
            }
        }
    }

    private fun render() {
        registerButton.text = if (sdk.isRegistered()) "Зарегистрировать телефон заново" else "Зарегистрировать телефон"
        registerButton.isEnabled = !busy
        recoveryButton.isEnabled = !busy && sdk.isRegistered()
        val transaction = current?.let { runCatching { it.signedTransaction() }.getOrNull() }
        if (transaction == null) {
            paymentCard.visibility = View.GONE
            return
        }
        // Built only from the signed values.
        paymentText.text =
            "${transaction.formattedAmount()} ${transaction.currency}\n" +
            "${transaction.beneficiaryDisplay()}\n" +
            "Референс: ${transaction.transactionReference}"
        val callNeeded = requiredCall != null && !callVerified
        callButton.visibility = if (requiredCall != null) View.VISIBLE else View.GONE
        callButton.text = if (requiredCall == VerificationChannel.VIDEO) "Видеозвонок с сотрудником банка" else "Аудиозвонок с сотрудником банка"
        callButton.isEnabled = !busy && callNeeded
        approveButton.isEnabled = !busy && !callNeeded
        offlineQrButton.visibility = if (requiredCall == null) View.VISIBLE else View.GONE
        offlineCodeButton.visibility = offlineQrButton.visibility
        offlineQrButton.isEnabled = !busy
        offlineCodeButton.isEnabled = !busy && offlineQr != null
        paymentCard.visibility = View.VISIBLE
    }

    private fun show(error: Throwable) {
        setStatus(
            when (error) {
                is NEXUSSignError.AuthenticationDenied -> "Подтверждение отменено."
                is NEXUSSignError.NoAuthenticationMethodEnrolled ->
                    "Включите блокировку экрана (PIN или пароль) и добавьте отпечаток или лицо в настройках телефона."
                is NEXUSSignError.BiometryUnavailable -> "Биометрия недоступна на этом телефоне."
                is NEXUSSignError.BiometryLockedOut -> "Слишком много неудачных попыток. Разблокируйте телефон и повторите."
                is NEXUSSignError.NotRegistered -> "Сначала зарегистрируйте телефон."
                is NEXUSSignError.AuthorizationExpired -> "Срок подтверждения истёк. Отправьте новый платёж."
                is NEXUSSignError.AuthorizationPayloadInvalid ->
                    "Данные платежа не совпадают с подписываемыми (${error.reason}). Ничего не подписано."
                is NEXUSSignError.CredentialInvalidated ->
                    "Биометрия на телефоне изменилась, ключ аннулирован. Зарегистрируйте телефон заново."
                is NEXUSSignError.ServerError ->
                    if (error.statusCode == 401) "Сервер не знает это устройство (его база создана заново). Нажмите «Зарегистрировать телефон заново»."
                    else "Сервер отклонил запрос (${error.statusCode}): ${error.serverMessage ?: ""}"
                is NEXUSSignError.NetworkUnavailable ->
                    "Нет связи с сервером. Телефон подключён кабелем, и выполнен ли adb reverse tcp:8091 tcp:8091?"
                is java.io.IOException ->
                    "Нет связи с демо-банком: ${error.message}. Он запущен, верен ли код сопряжения, выполнен ли adb reverse tcp:8091 tcp:8091?"
                else -> "${error::class.java.simpleName}: ${error.message}"
            },
        )
    }

    private fun setStatus(text: String) {
        statusView.text = text
    }

    private fun buildUi(): View {
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        root.addView(TextView(this).apply {
            text = "NEXUS-SIGN · демо"
            textSize = 22f
            setTypeface(typeface, Typeface.BOLD)
        })
        root.addView(TextView(this).apply {
            text = "Платёж подписывается ключом, который создан в аппаратном хранилище этого телефона и не покидает его."
            textSize = 14f
            setPadding(0, pad / 2, 0, pad)
        })
        pairingField = EditText(this).apply {
            hint = "Код сопряжения со страницы демо-банка (8 цифр)"
            inputType = InputType.TYPE_CLASS_NUMBER
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
                override fun afterTextChanged(s: Editable?) { pairingCode = s?.toString().orEmpty().filter(Char::isDigit) }
            })
        }
        root.addView(pairingField)
        registerButton = Button(this).apply { setOnClickListener { register() } }
        root.addView(registerButton)

        paymentCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            setBackgroundColor(0x331F6FEB)
            visibility = View.GONE
        }
        paymentCard.addView(TextView(this).apply {
            text = "Платёж на подтверждение"
            setTypeface(typeface, Typeface.BOLD)
        })
        paymentText = TextView(this).apply {
            textSize = 20f
            setPadding(0, pad / 2, 0, pad / 2)
        }
        paymentCard.addView(paymentText)
        callButton = Button(this).apply {
            visibility = View.GONE
            setOnClickListener { requestCall() }
        }
        paymentCard.addView(callButton)
        approveButton = Button(this).apply {
            text = "Подтвердить биометрией"
            setOnClickListener { approve() }
        }
        paymentCard.addView(approveButton)
        offlineQrButton = Button(this).apply {
            text = "Офлайн: получить QR"
            setOnClickListener { fetchOfflineQr() }
        }
        paymentCard.addView(offlineQrButton)
        offlineCodeButton = Button(this).apply {
            text = "Показать офлайн-код (без сети)"
            setOnClickListener { showOfflineCode() }
        }
        paymentCard.addView(offlineCodeButton)
        offlineCodeView = TextView(this).apply {
            textSize = 34f
            setTypeface(Typeface.MONOSPACE, Typeface.BOLD)
            visibility = View.GONE
        }
        root.addView(offlineCodeView)
        root.addView(paymentCard, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = pad })

        recoveryButton = Button(this).apply {
            text = "Создать фразу восстановления"
            setOnClickListener { createRecoveryPhrase() }
        }
        root.addView(recoveryButton, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply { topMargin = pad })

        statusView = TextView(this).apply {
            textSize = 15f
            setPadding(0, pad, 0, 0)
            setTextIsSelectable(true)
        }
        root.addView(statusView)
        return ScrollView(this).apply { addView(root) }
    }

    private companion object {
        // The demo bank's device port: the app's bank calls and the Auth Core
        // device endpoints, forwarded unchanged (demo/bank-backend/demo-bank.mjs).
        const val AUTH_CORE_URL = "http://127.0.0.1:8091"
        const val DEMO_BANK_URL = "http://127.0.0.1:8091"
        const val POLL_INTERVAL_MILLIS = 3_000L
    }
}
