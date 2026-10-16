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
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.nexis.nexussign.NEXUSSignConfig
import com.nexis.nexussign.NEXUSSignError
import com.nexis.nexussign.NEXUSSignSDK
import com.nexis.nexussign.NEXUSVerificationOutcome
import com.nexis.nexussign.NexusAuthorization
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
    private lateinit var recoveryButton: Button
    private lateinit var statusView: TextView

    private var current: NexusAuthorization? = null
    private var busy = false

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
        setContentView(buildUi())
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
        if (busy || current != null || !sdk.isRegistered()) return
        val id = runCatching { bank.pendingAuthorizationId() }.getOrNull() ?: return
        try {
            // The SDK checks that every displayed field matches the exact bytes it will sign.
            current = sdk.fetchAuthorization(id)
            setStatus("Банк просит подтвердить платёж. Проверьте сумму и получателя.")
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
        approveButton.isEnabled = !busy
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
        approveButton = Button(this).apply {
            text = "Подтвердить биометрией"
            setOnClickListener { approve() }
        }
        paymentCard.addView(approveButton)
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
