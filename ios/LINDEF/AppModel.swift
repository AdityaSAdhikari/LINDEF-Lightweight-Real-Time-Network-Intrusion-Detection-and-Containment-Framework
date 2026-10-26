import BackgroundTasks
import Foundation
import Observation
import UIKit
import UserNotifications

/// Everything the screens show, refreshed from the agent every two seconds
/// while the app is open.
@MainActor
@Observable
final class AppModel {
    var pairing: Pairing? = Pairing.load()
    var state: AgentState?
    var serverName: String?
    var notes: [Note] = []
    var problem: String?            // connection or server error shown at the top
    var actionError: String?        // a failed button press
    var pendingCode: PairingCode?   // opened from a lindef:// link, waiting for confirmation

    private var client: LindefClient?
    private var polling: Task<Void, Never>?

    init() {
        if let pairing { client = LindefClient(pairing) }
    }

    // MARK: Pairing

    func received(url: URL) {
        if let code = PairingCode(url.absoluteString) { pendingCode = code }
    }

    func pair(_ code: PairingCode, name: String) async throws {
        let pairing = try await LindefClient.pair(code, name: name)
        try pairing.save()
        Alerts.lastSeenId = 0
        self.pairing = pairing
        client = LindefClient(pairing)
        notes = []
        state = nil
        startPolling()                    // show the dashboard right away,
        await Alerts.requestPermission()  // then ask about notifications
    }

    func forget() {
        stopPolling()
        Pairing.delete()
        pairing = nil
        client = nil
        state = nil
        notes = []
        problem = nil
    }

    // MARK: Polling

    func startPolling() {
        guard client != nil, polling == nil else { return }
        polling = Task { [weak self] in
            var first = true
            while !Task.isCancelled {
                await self?.refresh(announce: !first)
                first = false
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    func stopPolling() {
        polling?.cancel()
        polling = nil
    }

    func refresh(announce: Bool = true) async {
        guard let client else { return }
        do {
            let state: AgentState = try await client.get("/v1/state")
            self.state = state
            problem = nil
            if serverName == nil {
                let health: Health = try await client.get("/v1/health")
                serverName = health.server
            }
            if state.notificationsLastId != notes.first?.id ?? 0 {
                await loadNotes(client, lastId: state.notificationsLastId, announce: announce)
            }
        } catch ClientError.unpaired {
            problem = ClientError.unpaired.errorDescription
            stopPolling()
        } catch {
            problem = error.localizedDescription
        }
    }

    private func loadNotes(_ client: LindefClient, lastId: Int, announce: Bool) async {
        guard let feed: NoteFeed = try? await client.get("/v1/notifications?after=0&limit=60") else { return }
        notes = feed.notifications.reversed()
        if feed.lastId < Alerts.lastSeenId { Alerts.lastSeenId = 0 }  // the agent restarted
        let fresh = feed.notifications.filter { $0.id > Alerts.lastSeenId }
        if announce || Alerts.lastSeenId > 0 { Alerts.post(fresh) }
        Alerts.lastSeenId = feed.lastId
    }

    // MARK: Commands

    func command(_ path: String, _ body: [String: Any] = [:]) async {
        guard let client else { return }
        do {
            state = try await client.post(path, body)
            actionError = nil
        } catch {
            actionError = error.localizedDescription
        }
    }

    func logFile() async -> URL? {
        guard let client, let data = try? await client.data("/v1/log.csv") else {
            actionError = "Couldn't download the detection log."
            return nil
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("attack_log.csv")
        try? data.write(to: url)
        return url
    }

    func modelInfo() async -> ModelInfo? {
        try? await client?.get("/v1/model")
    }
}

// MARK: - Notifications

/// Local notifications for new alerts at or above the chosen severity.
enum Alerts {
    static let severityKey = "alertsMinSeverity"
    private static let lastSeenKey = "alertsLastSeenId"
    private static let rank = ["NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 3, "CRITICAL": 4]

    static var lastSeenId: Int {
        get { UserDefaults.standard.integer(forKey: lastSeenKey) }
        set { UserDefaults.standard.set(newValue, forKey: lastSeenKey) }
    }

    static func requestPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
    }

    static func post(_ notes: [Note]) {
        let minimum = rank[UserDefaults.standard.string(forKey: severityKey) ?? "HIGH"] ?? 3
        let wanted = notes.filter { $0.kind == "error" || (rank[$0.severity] ?? 3) >= minimum }
        guard !wanted.isEmpty else { return }
        let content = UNMutableNotificationContent()
        if wanted.count > 3 {
            content.title = "LINDEF: \(wanted.count) new alerts"
            content.body = wanted.prefix(3).map(\.title).joined(separator: "\n")
        } else {
            for note in wanted.dropLast() { deliver(note.title, note.body) }
            content.title = wanted.last!.title
            content.body = wanted.last!.body
        }
        content.sound = .default
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }

    private static func deliver(_ title: String, _ body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil))
    }
}

/// Shows alerts as banners even while the app is open.
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationPresenter()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound, .list])
    }
}

// MARK: - Background refresh

/// While the app is in the background, iOS wakes it now and then (often every
/// 15 minutes or more, at the system's discretion) to check for new alerts.
/// Instant alerts on a locked phone would need push notifications through Apple's servers.
enum BackgroundRefresh {
    static let identifier = "com.lindef.phone.refresh"

    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            schedule()  // keep the chain going
            let work = Task {
                await check()
                task.setTaskCompleted(success: true)
            }
            task.expirationHandler = { work.cancel() }
        }
    }

    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        try? BGTaskScheduler.shared.submit(request)
    }

    static func check() async {
        guard let pairing = Pairing.load() else { return }
        let client = LindefClient(pairing)
        guard let feed: NoteFeed = try? await client.get("/v1/notifications?after=\(Alerts.lastSeenId)&limit=60") else { return }
        if feed.lastId < Alerts.lastSeenId {  // agent restarted
            Alerts.lastSeenId = feed.lastId
            return
        }
        Alerts.post(feed.notifications)
        Alerts.lastSeenId = feed.lastId
    }
}
