import SwiftUI
import UIKit

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @State private var showSettings = false
    @State private var confirmClear = false
    @State private var shareURL: URL?

    var body: some View {
        VStack(spacing: 0) {
          masthead
            .padding(.horizontal, 16)
            .background(Paper.paper)
          ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                if let state = model.state {
                    verdict(state)
                    controls(state)
                    ThreatsAtHand(recent: state.recentAttacks ?? state.recent)
                    metrics(state.metrics)
                    banners(state)
                    containment(state)
                    alerts
                    detections(state.recent)
                    distributions(state.charts)
                    monitoring(state)
                    footer
                } else {
                    VStack(alignment: .leading, spacing: 8) {
                        Text(model.problem == nil ? "Connecting to the Server" : "Can't Reach the LINDEF Server")
                            .font(Paper.serif(30, .medium))
                        if let problem = model.problem { Text(problem).foregroundStyle(Paper.ink2) }
                    }
                    .padding(.top, 8)
                }
            }
            .padding(.horizontal, 16)
            .padding(.top, 18)
            .padding(.bottom, 28)
          }
          .refreshable { await model.refresh() }
        }
        .foregroundStyle(Paper.ink)
        .sheet(isPresented: $showSettings) { SettingsView() }
        .sheet(item: $shareURL) { url in ShareSheet(items: [url]) }
        .confirmationDialog("Clear the detection log and lift all simulated containment?", isPresented: $confirmClear,
                            titleVisibility: .visible) {
            Button("Clear Logs", role: .destructive) { Task { await model.command("/v1/clear") } }
        }
    }

    // MARK: Header

    private var masthead: some View {
        HStack(alignment: .center, spacing: 10) {
            Text("LINDEF").font(Paper.serif(22, .semibold))
            Spacer()
            Circle().fill(model.problem == nil && model.state != nil ? Paper.ok : Paper.bad).frame(width: 8, height: 8)
            Text(model.problem == nil ? (model.serverName ?? model.pairing?.host ?? "") : "Offline")
                .font(.footnote).foregroundStyle(Paper.ink2).lineLimit(1)
            Button { showSettings = true } label: {
                Image(systemName: "gearshape").foregroundStyle(Paper.ink2)
            }
            .accessibilityLabel("Settings")
        }
        .padding(.top, 8).padding(.bottom, 10)
        .overlay(alignment: .bottom) { Rectangle().fill(Paper.ruleStrong).frame(height: 2) }
    }

    // MARK: The one sentence about right now

    private func verdict(_ s: AgentState) -> some View {
        let m = s.metrics
        let summary = "\(Words.plural(m.attacks, "attack")) in \(Words.plural(m.total, "flow")). " +
            "\(Words.plural(m.contained, "flow")) stopped by simulated containment."
        var title = "Traffic Looks Normal"
        var text = summary
        var alarm = false
        if let problem = model.problem {
            title = "Can't Reach the LINDEF Server"; text = problem; alarm = true
        } else if !s.models.loaded {
            title = "Detection Is Off on the Server"
            text = "The model files are missing there. Add them to the server's models folder, then restart the agent."
        } else if !s.error.isEmpty {
            title = "Detection Stopped Working"; text = s.error.components(separatedBy: "\n")[0]; alarm = true
        } else if !s.running && m.total == 0 {
            title = "Ready to Monitor \(model.serverName ?? "the server")"
            text = "Press Start to begin checking \(s.settings.mode == "live" ? "live traffic" : "the simulation file")."
        } else if !s.running {
            title = "Monitoring Is Stopped"
        } else if !s.containment.active.isEmpty {
            title = "\(Words.plural(s.containment.active.count, "Threat")) Contained"
            text = "Simulated: no real traffic was changed. " + summary
        }
        return VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(Paper.serif(30, .medium))
                .foregroundStyle(alarm ? Paper.severity("CRITICAL") : Paper.ink)
                .fixedSize(horizontal: false, vertical: true)
            Text(text).font(.subheadline).foregroundStyle(Paper.ink2).fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private func controls(_ s: AgentState) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Button("Start") { Task { await model.command("/v1/start") } }
                    .buttonStyle(PaperButtonStyle(primary: true)).disabled(s.running || !s.models.loaded)
                Button("Stop") { Task { await model.command("/v1/stop") } }
                    .buttonStyle(PaperButtonStyle()).disabled(!s.running)
                Button("Clear Logs") { confirmClear = true }.buttonStyle(PaperButtonStyle())
            }
            if let error = model.actionError { Text(error).font(.footnote).foregroundStyle(Paper.bad) }
        }
    }

    private func metrics(_ m: AgentState.Metrics) -> some View {
        let cells: [(String, String)] = [
            (m.total.formatted(), "Flows Checked"), (m.attacks.formatted(), "Detected Attacks"),
            (m.benign.formatted(), "Benign Flows"), (m.contained.formatted(), "Flows Stopped (Simulated)"),
        ]
        return VStack(spacing: 0) {
            Rectangle().fill(Paper.ruleStrong).frame(height: 1)
            Grid(horizontalSpacing: 0, verticalSpacing: 0) {
                ForEach(0..<2) { row in
                    GridRow {
                        ForEach(0..<2) { col in
                            let cell = cells[row * 2 + col]
                            VStack(alignment: .leading, spacing: 2) {
                                Text(cell.0).font(Paper.serif(26, .medium)).monospacedDigit()
                                Text(cell.1).font(.caption).foregroundStyle(Paper.ink3)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 10).padding(.leading, col == 0 ? 0 : 12)
                            .overlay(alignment: .leading) { if col == 1 { Rectangle().fill(Paper.rule).frame(width: 1) } }
                            .overlay(alignment: .top) { if row == 1 { Rectangle().fill(Paper.rule).frame(height: 1) } }
                        }
                    }
                }
            }
            Rectangle().fill(Paper.ruleStrong).frame(height: 1)
        }
    }

    @ViewBuilder
    private func banners(_ s: AgentState) -> some View {
        if !s.error.isEmpty {
            banner("The last check failed: \(s.error)", color: Paper.bad, tint: Paper.rose)
        }
        if !s.models.loaded {
            banner("Detection is off. The server is missing: " +
                   s.models.missing.map { ($0 as NSString).lastPathComponent }.joined(separator: ", "),
                   color: Paper.severity("MEDIUM"), tint: Paper.butter)
        }
    }

    private func banner(_ text: String, color: Color, tint: Color) -> some View {
        Text(text).font(.subheadline)
            .padding(10).frame(maxWidth: .infinity, alignment: .leading)
            .background(tint)
            .overlay(alignment: .leading) { Rectangle().fill(color).frame(width: 3) }
    }

    // MARK: Sections

    private func containment(_ s: AgentState) -> some View {
        let active = s.containment.active
        return PaperSection(title: "Containment", aside: "\(active.count) active, simulated", tint: Paper.rose) {
            if active.isEmpty {
                Text("Nothing is contained. When LINDEF detects an attack it blocks the source, throttles it, or isolates the affected host here.")
                    .font(.subheadline).foregroundStyle(Paper.ink3).padding(14)
            } else {
                ForEach(Array(active.prefix(12).enumerated()), id: \.element.id) { index, action in
                    RuledRow(last: index == min(active.count, 12) - 1) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text("\(Words.action(action.action)) \(action.target)").font(.subheadline.weight(.semibold))
                                Spacer()
                                SeverityLabel(level: action.severity)
                            }
                            Text("\(Words.attack(action.attack))\(action.triggers > 1 ? " (\(action.triggers) times)" : ""). " +
                                 "\(Words.until(action.expires)). \(Words.plural(action.flowsStopped, "flow")) stopped.")
                                .font(.footnote).foregroundStyle(Paper.ink2)
                        }
                    }
                }
                Text("Lift containment from the desktop app. No real traffic is changed.")
                    .font(.caption).foregroundStyle(Paper.ink3).padding(.horizontal, 14).padding(.vertical, 8)
            }
        }
    }

    private var alerts: some View {
        PaperSection(title: "Alerts", aside: model.notes.isEmpty ? nil : Words.plural(model.notes.count, "recent alert"),
                     tint: Paper.peach) {
            if model.notes.isEmpty {
                Text("No alerts yet.").font(.subheadline).foregroundStyle(Paper.ink3).padding(14)
            } else {
                let shown = Array(model.notes.prefix(8))
                ForEach(Array(shown.enumerated()), id: \.element.id) { index, note in
                    RuledRow(last: index == shown.count - 1) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                if note.severity != "NONE" {
                                    RoundedRectangle(cornerRadius: 2).fill(Paper.severity(note.severity)).frame(width: 9, height: 9)
                                }
                                Text(note.title).font(.subheadline.weight(.semibold))
                                Spacer(minLength: 4)
                                Text(Words.ago(note.time)).font(.caption).foregroundStyle(Paper.ink3)
                            }
                            Text(note.body).font(.footnote).foregroundStyle(Paper.ink2)
                        }
                    }
                }
            }
        }
    }

    private func detections(_ recent: [Detection]) -> some View {
        let rows = Array(recent.reversed().prefix(20))
        return PaperSection(title: "Recent Detections", aside: "Newest first", tint: Paper.green) {
            if rows.isEmpty {
                Text("No traffic checked yet. Press Start to begin.").font(.subheadline).foregroundStyle(Paper.ink3).padding(14)
            } else {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, r in
                    RuledRow(last: index == rows.count - 1) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(r.status == "ATTACK" ? Words.attack(r.attack) : "Benign").font(.subheadline.weight(.semibold))
                                if let contained = r.contained {
                                    Text(contained.capitalized).font(.footnote.weight(.semibold)).foregroundStyle(Paper.severity("CRITICAL"))
                                }
                                Spacer()
                                SeverityLabel(level: r.severity)
                            }
                            Text("\(Words.address(r.sourceIP, r.sourcePort)) to \(Words.address(r.destinationIP, r.destinationPort))")
                                .font(.footnote).foregroundStyle(Paper.ink2)
                            Text("\(r.time). Probability \(r.probability.map { String(format: "%.4f", $0) } ?? "n/a"). \(Words.response(r.response))")
                                .font(.caption).foregroundStyle(Paper.ink3).monospacedDigit()
                        }
                    }
                    .overlay(alignment: .leading) {
                        if r.status == "ATTACK" { Rectangle().fill(Paper.severity("HIGH")).frame(width: 3) }
                    }
                }
            }
        }
    }

    private func distributions(_ c: AgentState.Charts) -> some View {
        PaperSection(title: "Distributions", aside: "Since last clear", tint: Paper.lavender) {
            VStack(alignment: .leading, spacing: 14) {
                bars("Attack and Benign", c.status) { $0 == "ATTACK" ? Paper.severity("HIGH") : Paper.severity("NONE") }
                    label: { $0 == "ATTACK" ? "Attack" : "Benign" }
                bars("Severity", c.severity) { Paper.severity($0) } label: { Words.severity($0) }
                bars("Attack Types", c.attacks) { _ in Paper.accent } label: { Words.attack($0) }
                bars("Recommended Responses", c.responses) { _ in Paper.accent } label: { Words.response($0) }
            }
            .padding(14)
        }
    }

    private func bars(_ title: String, _ counts: [Count], color: @escaping (String) -> Color,
                      label: @escaping (String) -> String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(Paper.serif(15, .semibold))
            if counts.isEmpty {
                Text("Nothing yet.").font(.footnote).foregroundStyle(Paper.ink3)
            }
            let top = max(counts.map(\.value).max() ?? 1, 1)
            ForEach(counts.prefix(6)) { count in
                HStack(spacing: 8) {
                    Text(label(count.label)).font(.footnote).lineLimit(1).frame(width: 110, alignment: .leading)
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Rectangle().fill(Paper.paper2).overlay(Rectangle().stroke(Paper.rule))
                            Rectangle().fill(color(count.label)).frame(width: geo.size.width * CGFloat(count.value) / CGFloat(top))
                        }
                    }
                    .frame(height: 10)
                    Text(count.value.formatted()).font(.footnote).monospacedDigit().frame(width: 40, alignment: .trailing)
                }
            }
        }
    }

    private func monitoring(_ s: AgentState) -> some View {
        PaperSection(title: "Monitoring", tint: Paper.blue) {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Traffic Source").font(.subheadline.weight(.semibold))
                    Text(s.settings.mode == "live" ? "Live capture on \(s.settings.interfaceId)" : "Simulation File")
                        .font(.subheadline).foregroundStyle(Paper.ink2)
                    Text("Switch between simulation and live capture on the desktop.").font(.caption).foregroundStyle(Paper.ink3)
                }
                SettingSlider(title: "Check Every", value: s.settings.refreshSeconds, range: 0.5...10, step: 0.5,
                              format: { String(format: "%g s", $0) }) { v in
                    Task { await model.command("/v1/settings", ["refresh_seconds": v]) }
                }
                SettingSlider(title: "Flows per Check (Simulation)", value: Double(s.settings.rowsPerStep), range: 1...100, step: 1,
                              format: { "\(Int($0))" }) { v in
                    Task { await model.command("/v1/settings", ["rows_per_step": Int(v)]) }
                }
                SettingSlider(title: "Capture Length (Live)", value: Double(s.settings.captureDuration), range: 2...20, step: 1,
                              format: { "\(Int($0)) s" }) { v in
                    Task { await model.command("/v1/settings", ["capture_duration": Int(v)]) }
                }
            }
            .padding(14)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 14) {
            Button("Share Detection Log") {
                Task { shareURL = await model.logFile() }
            }
            .buttonStyle(PaperButtonStyle())
            ModelDetails()
        }
    }
}

/// The live part of the dashboard: the newest attacks slide in at the top,
/// so the headline above can stay still.
struct ThreatsAtHand: View {
    let recent: [Detection]
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let threats = Array(recent.filter { $0.status == "ATTACK" }.suffix(4).reversed())
        VStack(alignment: .leading, spacing: 8) {
            Text("Threats at Hand").font(Paper.serif(17, .semibold))
            if threats.isEmpty {
                Text("No attacks detected yet.").font(.footnote).foregroundStyle(Paper.ink3)
            }
            ForEach(threats) { r in
                let done = r.contained ?? ["BLOCK_IP": "BLOCKED", "THROTTLE_IP": "THROTTLED", "ISOLATE_HOST": "ISOLATED"][r.response]
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 7) {
                        RoundedRectangle(cornerRadius: 2).fill(Paper.severity(r.severity)).frame(width: 9, height: 9)
                        Text(Words.attack(r.attack)).font(.subheadline.weight(.semibold))
                        Text(done?.capitalized ?? "Watching").font(.footnote.weight(.semibold))
                            .foregroundStyle(done == nil ? Paper.ink3 : Paper.severity("CRITICAL"))
                        Spacer()
                        Text(r.time).font(.caption).foregroundStyle(Paper.ink3).monospacedDigit()
                    }
                    Text("from \(Words.address(r.sourceIP, nil)) to \(Words.address(r.destinationIP, nil))")
                        .font(.caption).foregroundStyle(Paper.ink2).padding(.leading, 16)
                }
                .transition(reduceMotion ? .opacity : .move(edge: .top).combined(with: .opacity))
            }
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .top) { Rectangle().fill(Paper.rule).frame(height: 1) }
        .animation(.easeOut(duration: 0.4), value: threats.map(\.id))
    }
}

/// A slider that only sends the new value when the finger lifts.
struct SettingSlider: View {
    let title: String
    let value: Double
    let range: ClosedRange<Double>
    let step: Double
    let format: (Double) -> String
    let commit: (Double) -> Void
    @State private var draft: Double?

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(title).font(.subheadline.weight(.semibold))
                Spacer()
                Text(format(draft ?? value)).font(.subheadline).foregroundStyle(Paper.ink2).monospacedDigit()
            }
            Slider(value: Binding(get: { draft ?? value }, set: { draft = $0 }), in: range, step: step) { editing in
                if !editing, let draft {
                    commit(draft)
                    self.draft = nil
                }
            }
            .tint(Paper.accent)
        }
    }
}

struct ModelDetails: View {
    @Environment(AppModel.self) private var model
    @State private var info: ModelInfo?
    @State private var expanded = false
    @State private var showFeatures = false

    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(alignment: .leading, spacing: 6) {
                if let info {
                    Text("Expected Features: \(info.featureCount)").font(.footnote)
                    Text("Feature Medians Loaded: \(info.mediansLoaded ? "Yes" : "No")").font(.footnote)
                    Toggle("Show Expected Feature Columns", isOn: $showFeatures).font(.footnote).tint(Paper.accent)
                    if showFeatures {
                        ForEach(info.featureColumns, id: \.self) { Text($0).font(.caption).foregroundStyle(Paper.ink2) }
                    }
                } else {
                    Text("Loading").font(.footnote).foregroundStyle(Paper.ink3)
                }
            }
            .padding(.top, 8)
        } label: {
            Text("Model and Feature Details").font(Paper.serif(16, .semibold)).foregroundStyle(Paper.ink)
        }
        .tint(Paper.ink2)
        .onChange(of: expanded) { _, open in
            if open && info == nil { Task { info = await model.modelInfo() } }
        }
    }
}

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @AppStorage("appearance") private var appearance = "light"
    @AppStorage(Alerts.severityKey) private var minSeverity = "HIGH"
    @State private var confirmForget = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Appearance") {
                    Picker("Theme", selection: $appearance) {
                        Text("Paper (Light)").tag("light")
                        Text("Dark").tag("dark")
                        Text("Match the Phone").tag("system")
                    }
                }
                Section {
                    Picker("Alert Me From", selection: $minSeverity) {
                        Text("Low Severity").tag("LOW")
                        Text("Medium Severity").tag("MEDIUM")
                        Text("High Severity").tag("HIGH")
                        Text("Critical Only").tag("CRITICAL")
                    }
                } header: {
                    Text("Notifications")
                } footer: {
                    Text("LINDEF keeps one notification that updates in place, at most once a minute. Nothing pops up while the app is open. In the background, iOS checks now and then, often every 15 minutes or more.")
                }
                if let pairing = model.pairing {
                    Section {
                        LabeledContent("Server", value: model.serverName ?? pairing.host)
                        LabeledContent("Address", value: "\(pairing.host):\(String(pairing.port))")
                        LabeledContent("This Phone", value: pairing.name)
                        LabeledContent("Certificate", value: String(pairing.fingerprint.prefix(16)) + "...")
                        Button("Forget This Server", role: .destructive) { confirmForget = true }
                    } header: {
                        Text("Connection")
                    } footer: {
                        Text("To fully revoke this phone, also unlink it from the desktop's Devices list.")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog("Forget this server? You will need a new pairing code to reconnect.",
                                isPresented: $confirmForget, titleVisibility: .visible) {
                Button("Forget Server", role: .destructive) {
                    model.forget()
                    dismiss()
                }
            }
        }
        .tint(Paper.accent)
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}
