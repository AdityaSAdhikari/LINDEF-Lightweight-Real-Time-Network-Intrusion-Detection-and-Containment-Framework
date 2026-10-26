import CryptoKit
import Foundation
import Security

// MARK: - What the agent sends (see docs/desktop_app_spec.md)

struct AgentState: Decodable {
    let running: Bool
    let error: String
    let settings: Settings
    let models: Models
    let simulatedAddresses: Bool
    let lastId: Int
    let notificationsLastId: Int
    let metrics: Metrics
    let containment: Containment
    let recent: [Detection]
    let recentAttacks: [Detection]?
    let charts: Charts
    let labels: Labels?

    enum CodingKeys: String, CodingKey {
        case running, error, settings, models, metrics, containment, recent, charts, labels
        case recentAttacks = "recent_attacks"
        case simulatedAddresses = "simulated_addresses", lastId = "last_id", notificationsLastId = "notifications_last_id"
    }

    struct Models: Decodable { let loaded: Bool; let missing: [String] }
    struct Metrics: Decodable { let total, attacks, benign, contained: Int; let latest: String }

    struct Settings: Decodable {
        let mode: String
        let refreshSeconds: Double
        let rowsPerStep: Int
        let captureDuration: Int
        let simulationCsv: String
        let interfaceId: String

        enum CodingKeys: String, CodingKey {
            case mode, refreshSeconds = "refresh_seconds", rowsPerStep = "rows_per_step",
                 captureDuration = "capture_duration", simulationCsv = "simulation_csv", interfaceId = "interface_id"
        }
    }

    struct Containment: Decodable {
        let active: [Action]
        let flowsStopped: Int
        enum CodingKeys: String, CodingKey { case active, flowsStopped = "flows_stopped" }
    }

    struct Labels: Decodable { let attacks: [String: String]; let responses: [String: String] }
    struct Charts: Decodable { let status, severity, attacks, responses: [Count] }
}

struct Detection: Decodable, Identifiable {
    let id: Int
    let time, status, attack, severity, response: String
    let probability: Double?
    let sourceIP, sourcePort, destinationIP, destinationPort, contained: String?

    enum CodingKeys: String, CodingKey {
        case id = "ID", time = "Time", status = "Status", attack = "Attack", severity = "Severity", response = "Response"
        case probability = "Attack Probability", sourceIP = "Source IP", sourcePort = "Source Port"
        case destinationIP = "Destination IP", destinationPort = "Destination Port", contained = "Contained"
    }
}

struct Action: Decodable, Identifiable {
    let id: Int
    let action, target, attack, severity: String
    let started: Int
    let expires: Int?
    let triggers: Int
    let flowsStopped: Int

    enum CodingKeys: String, CodingKey {
        case id, action, target, attack, severity, started, expires, triggers, flowsStopped = "flows_stopped"
    }
}

struct Note: Decodable, Identifiable {
    let id: Int
    let time: Int
    let kind, severity, title, body: String
}

struct NoteFeed: Decodable {
    let notifications: [Note]
    let lastId: Int
    enum CodingKeys: String, CodingKey { case notifications, lastId = "last_id" }
}

struct ModelInfo: Decodable {
    let loaded: Bool
    let featureCount: Int
    let mediansLoaded: Bool
    let featureColumns: [String]
    enum CodingKeys: String, CodingKey {
        case loaded, featureCount = "feature_count", mediansLoaded = "medians_loaded", featureColumns = "feature_columns"
    }
}

/// One `["label", count]` pair from a chart.
struct Count: Decodable, Identifiable {
    let label: String
    let value: Int
    var id: String { label }

    init(from decoder: Decoder) throws {
        var pair = try decoder.unkeyedContainer()
        label = try pair.decode(String.self)
        value = try pair.decode(Int.self)
    }
}

struct Health: Decodable {
    let server: String
    let role: String
}

// MARK: - Pairing

/// `lindef://HOST:PORT?pair=CODE&fp=SHA256` from the desktop's QR code.
struct PairingCode: Identifiable {
    let host: String
    let port: Int
    let code: String
    let fingerprint: String
    var id: String { code }

    init?(_ text: String) {
        guard let parts = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              parts.scheme == "lindef", let host = parts.host, !host.isEmpty, let port = parts.port else { return nil }
        let query = Dictionary((parts.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
        guard let code = query["pair"], !code.isEmpty,
              let fp = query["fp"]?.lowercased(), fp.count == 64, fp.allSatisfy(\.isHexDigit) else { return nil }
        self.host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        self.port = port
        self.code = code
        self.fingerprint = fp
    }
}

/// What this phone keeps after pairing. Stored in the Keychain.
struct Pairing: Codable {
    let host: String
    let port: Int
    let fingerprint: String
    let token: String
    let deviceId: String
    let name: String

    private static let service = "com.lindef.phone"
    private static let account = "pairing"

    static func load() -> Pairing? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                    kSecAttrAccount as String: account, kSecReturnData as String: true]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return try? JSONDecoder().decode(Pairing.self, from: data)
    }

    func save() throws {
        Pairing.delete()
        let item: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: Pairing.service,
                                   kSecAttrAccount as String: Pairing.account,
                                   kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                   kSecValueData as String: try JSONEncoder().encode(self)]
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ClientError.server("Paired, but the phone couldn't save the pairing to the Keychain (error \(status)).")
        }
    }

    static func delete() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                       kSecAttrAccount as String: account] as CFDictionary)
    }
}

// MARK: - Pinned HTTPS client

enum ClientError: LocalizedError {
    case unpaired
    case certificate(String)
    case server(String)
    case network(String)

    var errorDescription: String? {
        switch self {
        case .unpaired: return "This phone was unlinked from the LINDEF server. Scan a new code from the desktop."
        case .certificate(let host): return "\(host) presented a different certificate than the one it was paired with. If the agent was reset, pair again."
        case .server(let message), .network(let message): return message
        }
    }
}

/// Accepts the server only if its certificate's SHA-256 fingerprint matches the paired one.
/// The check runs during the TLS handshake, before the token is ever sent.
final class PinningDelegate: NSObject, URLSessionDelegate {
    let fingerprint: String
    private(set) var mismatch = false

    init(fingerprint: String) { self.fingerprint = fingerprint }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let digest = SHA256.hash(data: SecCertificateCopyData(leaf) as Data).map { String(format: "%02x", $0) }.joined()
        if digest == fingerprint {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            mismatch = true
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

final class LindefClient {
    let host: String
    let port: Int
    private let token: String?
    private let delegate: PinningDelegate
    private let session: URLSession

    init(host: String, port: Int, fingerprint: String, token: String?) {
        self.host = host
        self.port = port
        self.token = token
        delegate = PinningDelegate(fingerprint: fingerprint)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    convenience init(_ pairing: Pairing) {
        self.init(host: pairing.host, port: pairing.port, fingerprint: pairing.fingerprint, token: pairing.token)
    }

    deinit { session.invalidateAndCancel() }

    func get<T: Decodable>(_ path: String) async throws -> T {
        try JSONDecoder().decode(T.self, from: try await send("GET", path, body: nil))
    }

    func post<T: Decodable>(_ path: String, _ body: [String: Any] = [:]) async throws -> T {
        try JSONDecoder().decode(T.self, from: try await send("POST", path, body: body))
    }

    func data(_ path: String) async throws -> Data {
        try await send("GET", path, body: nil)
    }

    private func send(_ method: String, _ path: String, body: [String: Any]?) async throws -> Data {
        var host = self.host
        if host.contains(":") { host = "[\(host)]" }  // IPv6
        guard let url = URL(string: "https://\(host):\(port)\(path)") else { throw ClientError.network("Bad server address.") }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body { request.httpBody = try JSONSerialization.data(withJSONObject: body) }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            if delegate.mismatch { throw ClientError.certificate("\(self.host):\(port)") }
            throw ClientError.network("Can't reach the LINDEF server at \(self.host):\(port). Check that the agent is running and this phone is on the same network.")
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 401 && token != nil { throw ClientError.unpaired }
        guard (200..<300).contains(status) else {
            let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
            throw ClientError.server(message ?? "The server answered with status \(status).")
        }
        return data
    }

    /// Trade a one-time pairing code for this phone's own token.
    static func pair(_ code: PairingCode, name: String) async throws -> Pairing {
        let client = LindefClient(host: code.host, port: code.port, fingerprint: code.fingerprint, token: nil)
        struct Claim: Decodable { let device_id: String; let role: String; let token: String }
        let claim: Claim = try await client.post("/v1/pair/claim", ["code": code.code, "name": name])
        return Pairing(host: code.host, port: code.port, fingerprint: code.fingerprint,
                       token: claim.token, deviceId: claim.device_id, name: name)
    }
}
