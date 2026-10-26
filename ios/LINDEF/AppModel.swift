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
    var state: AgentState? {
        didSet {
            if let labels = state?.labels { Words.attackLabels = labels.attacks; Words.responseLabels = labels.responses }
        }
    }
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
        Alerts.clearSummary()  // the alerts list is on screen now
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
        _ = fresh  // the open app lists them; no notification while it is on screen
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

/// Alerts as notifications, without spam. Rules:
/// - Nothing is shown while the app is open (the alerts list is on screen).
/// - There is only ever one LINDEF notification. Each new one replaces it in
///   place ("6 new alerts. Latest: ..."), so they never pile up.
/// - At most one a minute; critical alerts and errors may come after 15 seconds.
///   Alerts that arrive in between are counted into the next summary.
enum Alerts {
    static let severityKey = "alertsMinSeverity"
    private static let lastSeenKey = "alertsLastSeenId"
    private static let lastShownKey = "alertsLastShown"
    private static let pendingKey = "alertsPending"
    private static let latestTitleKey = "alertsLatestTitle"
    private static let latestBodyKey = "alertsLatestBody"
    private static let summaryId = "lindef-alerts"
    static let quietSeconds: TimeInterval = 60
    static let urgentSeconds: TimeInterval = 15
    private static let rank = ["NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "UNKNOWN": 3, "CRITICAL": 4]

    static var lastSeenId: Int {
        get { UserDefaults.standard.integer(forKey: lastSeenKey) }
        set { UserDefaults.standard.set(newValue, forKey: lastSeenKey) }
    }

    static func requestPermission() async {
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])
    }

    /// Count new alerts and show one summary if the cooldown allows. Call with
    /// an empty list to flush alerts held back by an earlier cooldown.
    static func post(_ notes: [Note]) {
        let defaults = UserDefaults.standard
        let minimum = rank[defaults.string(forKey: severityKey) ?? "HIGH"] ?? 3
        let wanted = notes.filter { $0.kind == "error" || (rank[$0.severity] ?? 3) >= minimum }
        let pending = defaults.integer(forKey: pendingKey) + wanted.count
        defaults.set(pending, forKey: pendingKey)
        if let latest = wanted.last {
            defaults.set(latest.title, forKey: latestTitleKey)
            defaults.set(latest.body, forKey: latestBodyKey)
        }
        guard pending > 0 else { return }

        let urgent = wanted.contains { $0.kind == "error" || $0.severity == "CRITICAL" }
        let since = Date().timeIntervalSince1970 - defaults.double(forKey: lastShownKey)
        guard since >= (urgent ? urgentSeconds : quietSeconds) else { return }  // counted into the next summary

        let title = defaults.string(forKey: latestTitleKey) ?? "New alerts"
        let content = UNMutableNotificationContent()
        if pending == 1 {
            content.title = title
            content.body = defaults.string(forKey: latestBodyKey) ?? ""
        } else {
            content.title = "LINDEF: \(pending) New Alerts"
            content.body = "Latest: \(title). Open LINDEF for the full list."
        }
        content.threadIdentifier = summaryId
        content.sound = since >= 10 * 60 || urgent ? .default : nil  // silent when it updates a recent one
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: summaryId, content: content, trigger: nil))
        defaults.set(Date().timeIntervalSince1970, forKey: lastShownKey)
        defaults.set(0, forKey: pendingKey)
    }

    /// Opening the app shows every alert, so the summary has done its job.
    static func clearSummary() {
        UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [summaryId])
        UserDefaults.standard.set(0, forKey: pendingKey)
    }
}

/// Keeps a summary that lands while the app is open out of the way (list only, no banner).
final class NotificationPresenter: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationPresenter()

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.list])
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
