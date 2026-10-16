package com.nexis.nexussign.demo

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * The app's own backend: the demo bank (demo/bank-backend/demo-bank.mjs).
 * A real bank app talks to its bank's backend in the same places: to get a
 * BOOTSTRAP token for enrolment, to report the enrolled device, and to learn
 * which authorization the customer should review (here by polling; in
 * production by the bank's push or by NEXUS-SIGN secure push).
 */
class DemoBank(
    private val baseUrl: String,
    /** The code shown on the demo bank's operator page (FI-016). */
    private val pairingCode: () -> String,
) {

    suspend fun bootstrapToken(): String =
        JSONObject(request("POST", "/app/bootstrap-token", "{}")).getString("token")

    suspend fun registered(credentialId: String) {
        request("POST", "/app/registered", JSONObject().put("credentialId", credentialId).toString())
    }

    suspend fun pendingAuthorizationId(): String? =
        JSONObject(request("GET", "/app/pending", null)).optString("authorizationId").ifEmpty { null }

    private suspend fun request(method: String, path: String, body: String?): String = withContext(Dispatchers.IO) {
        val connection = (URL(baseUrl + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("X-Demo-Pairing-Code", pairingCode())
            connectTimeout = 5_000
            readTimeout = 10_000
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (code !in 200..299) throw IOException("demo bank answered $code: $text")
            text
        } finally {
            connection.disconnect()
        }
    }
}
