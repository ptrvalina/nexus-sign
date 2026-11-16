import XCTest
@testable import NEXUSSign

/// Decoding of the customer-call model from the JSON Auth Core sends
/// (`toCall` in customerCallService.ts). The `operator` field is a Swift
/// keyword; the property is escaped and keeps the wire name.
final class AccountModelsTests: XCTestCase {
    private func call(operator name: String?) throws -> NexusCustomerCall {
        let operatorJSON = name.map { "\"\($0)\"" } ?? "null"
        let json = """
        {"calls":[{"callId":"00000000-0000-4000-8000-0000000000c1","nexusId":"123456789",
        "credentialId":"00000000-0000-4000-8000-0000000000c2","channel":"AUDIO","topic":"Card blocked",
        "conversationId":null,"state":"CONNECTED","operator":\(operatorJSON),
        "createdAt":"2026-11-16T10:00:00.000Z","expiresAt":"2026-11-16T10:30:00.000Z",
        "answeredAt":"2026-11-16T10:01:00.000Z","endedAt":null,"endedBy":null,"endReason":null}]}
        """
        return try JSONDecoder().decode(CustomerCallList.self, from: Data(json.utf8)).calls[0]
    }

    func testCustomerCallDecodesTheOperator() throws {
        let decoded = try call(operator: "agent.anna")
        XCTAssertEqual(decoded.`operator`, "agent.anna")
        XCTAssertEqual(decoded.state, "CONNECTED")
        XCTAssertEqual(decoded.channel, "AUDIO")
        XCTAssertNil(decoded.conversationId)
    }

    func testCustomerCallWithoutAnOperator() throws {
        XCTAssertNil(try call(operator: nil).`operator`)
    }
}
