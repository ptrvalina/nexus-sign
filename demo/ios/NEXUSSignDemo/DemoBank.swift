import Foundation
import NEXUSSign

/// The app's own backend: the demo bank (demo/bank-backend/demo-bank.mjs),
/// reached at the same address as Auth Core through the demo bank's device
/// port. A real bank app calls its bank's backend in the same places: for a
/// BOOTSTRAP token, to report the enrolled device, and to learn which
/// authorization the customer should review (here by polling; in production by
/// the bank's push or NEXUS-SIGN secure push).
struct DemoBank {
    let baseURL: URL
    /// The code shown on the demo bank's operator page; without it the demo
    /// bank issues no enrolment token.
    let pairingCode: String

    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    func bootstrapToken() async throws -> String {
        let object = try await request("POST", "app/bootstrap-token", body: Data("{}".utf8))
        guard let token = object["token"] as? String else { throw Failure(message: "the demo bank sent no token") }
        return token
    }

    func registered(credentialID: String) async throws {
        _ = try await request("POST", "app/registered", body: try JSONSerialization.data(withJSONObject: ["credentialId": credentialID]))
    }

    /// The payment to review, and the call the bank's policy asks for first (AUDIO, VIDEO or none).
    func pending() async throws -> (authorizationID: String, call: VerificationChannel?)? {
        let body = try await request("GET", "app/pending", body: nil)
        guard let id = body["authorizationId"] as? String else { return nil }
        return (id, (body["call"] as? String).flatMap(VerificationChannel.init(rawValue:)))
    }

    /// The content of the offline QR code for the waiting payment. In a branch
    /// the bank's screen shows it; the demo hands it to the app while online.
    func offlineChallenge() async throws -> String {
        let body = try await request("GET", "app/offline-challenge", body: nil)
        guard let qr = body["qrPayload"] as? String else { throw Failure(message: "the demo bank sent no QR content") }
        return qr
    }

    private func request(_ method: String, _ path: String, body: Data?) async throws -> [String: Any] {
        var request = URLRequest(url: baseURL.appendingPathComponent(path), timeoutInterval: 10)
        request.httpMethod = method
        request.setValue(pairingCode, forHTTPHeaderField: "X-Demo-Pairing-Code")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw Failure(message: "the demo bank answered \(status): \(String(decoding: data, as: UTF8.self))")
        }
        return (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }
}
