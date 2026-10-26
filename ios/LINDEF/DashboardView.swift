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
                        Text(model.problem == nil ? "Connecting to the server" : "Can't reach the LINDEF server")
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
            Button("Clear logs", role: .destructive) { Task { await model.command("/v1/clear") } }
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
        var title = "Traffic looks normal"
        var text = summary
        var alarm = false
        let newest = s.containment.active.first
        let latest = s.recent.last
        if let problem = model.problem {
            title = "Can't reach the LINDEF server"; text = problem; alarm = true
        } else if !s.models.loaded {
            title = "Detection is off on the server"
            text = "The model files are missing there. Add them to the server's models folder, then restart the agent."
        } else if !s.error.isEmpty {
            title = "Detection stopped working"; text = s.error.components(separatedBy: "\n")[0]; alarm = true
        } else if !s.running && m.total == 0 {
            title = "Ready to monitor \(model.serverName ?? "the server")"
            text = "Press Start to begin checking \(s.settings.mode == "live" ? "live traffic" : "the simulation file")."
        } else if !s.running {
            title = "Monitoring is stopped"
        } else if let newest, Int(Date().timeIntervalSince1970) - newest.started < 20 {
            title = "\(Words.actionPast(newest.action)) \(newest.target) after \(Words.article(newest.attack)) \(newest.attack) attack"
            text = "Simulated: no real traffic was changed. " + summary
            alarm = newest.severity == "HIGH" || newest.severity == "CRITICAL"
        } else if let latest, latest.status == "ATTACK" {
            title = "\(latest.attack) attack from \(latest.sourceIP ?? "an unknown address")"; alarm = true
        } else if !s.containment.active.isEmpty {
            title = "\(Words.plural(s.containment.active.count, "threat")) contained"
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
                Button("Clear logs") { confirmClear = true }.buttonStyle(PaperButtonStyle())
            }
            if let error = model.actionError { Text(error).font(.footnote).foregroundStyle(Paper.bad) }
        }
    }

    private func metrics(_ m: AgentState.Metrics) -> some View {
        let cells: [(String, String)] = [
            (m.total.formatted(), "Flows checked"), (m.attacks.formatted(), "Detected attacks"),
            (m.benign.formatted(), "Benign flows"), (m.contained.formatted(), "Flows stopped (simulated)"),
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
                            Text("\(action.attack)\(action.triggers > 1 ? " (\(action.triggers) times)" : ""). " +
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
        return PaperSection(title: "Recent detections", aside: "Newest first", tint: Paper.green) {
            if rows.isEmpty {
                Text("No traffic checked yet. Press Start to begin.").font(.subheadline).foregroundStyle(Paper.ink3).padding(14)
            } else {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, r in
                    RuledRow(last: index == rows.count - 1) {
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(r.status == "ATTACK" ? r.attack : "Benign").font(.subheadline.weight(.semibold))
                                if let contained = r.contained {
                                    Text(contained.capitalized).font(.footnote.weight(.semibold)).foregroundStyle(Paper.severity("CRITICAL"))
                                }
                                Spacer()
                                SeverityLabel(level: r.severity)
                            }
                            Text("\(Words.address(r.sourceIP, r.sourcePort)) to \(Words.address(r.destinationIP, r.destinationPort))")
                                .font(.footnote).foregroundStyle(Paper.ink2)
                            Text("\(r.time). Probability \(r.probability.map { String(format: "%.4f", $0) } ?? "n/a"). \(r.response)")
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
                bars("Attack and benign", c.status) { $0 == "ATTACK" ? Paper.severity("HIGH") : Paper.severity("NONE") }
                    label: { $0 == "ATTACK" ? "Attack" : "Benign" }
                bars("Severity", c.severity) { Paper.severity($0) } label: { Words.severity($0) }
                bars("Attack types", c.attacks) { _ in Paper.accent } label: { $0 }
                bars("Recommended responses", c.responses) { _ in Paper.accent } label: { $0 }
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
                    Text("Traffic source").font(.subheadline.weight(.semibold))
                    Text(s.settings.mode == "live" ? "Live capture on \(s.settings.interfaceId)" : "Simulation file")
                        .font(.subheadline).foregroundStyle(Paper.ink2)
                    Text("Switch between simulation and live capture on the desktop.").font(.caption).foregroundStyle(Paper.ink3)
                }
                SettingSlider(title: "Check every", value: s.settings.refreshSeconds, range: 0.5...10, step: 0.5,
                              format: { String(format: "%g s", $0) }) { v in
                    Task { await model.command("/v1/settings", ["refresh_seconds": v]) }
                }
                SettingSlider(title: "Flows per check (simulation)", value: Double(s.settings.rowsPerStep), range: 1...100, step: 1,
                              format: { "\(Int($0))" }) { v in
                    Task { await model.command("/v1/settings", ["rows_per_step": Int(v)]) }
                }
                SettingSlider(title: "Capture length (live)", value: Double(s.settings.captureDuration), range: 2...20, step: 1,
                              format: { "\(Int($0)) s" }) { v in
                    Task { await model.command("/v1/settings", ["capture_duration": Int(v)]) }
                }
            }
            .padding(14)
        }
    }

    private var footer: some View {
        VStack(alignment: .leading, spacing: 14) {
            Button("Share detection log") {
                Task { shareURL = await model.logFile() }
            }
            .buttonStyle(PaperButtonStyle())
            ModelDetails()
        }
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
                    Text("Expected features: \(info.featureCount)").font(.footnote)
                    Text("Feature medians loaded: \(info.mediansLoaded ? "Yes" : "No")").font(.footnote)
                    Toggle("Show expected feature columns", isOn: $showFeatures).font(.footnote).tint(Paper.accent)
                    if showFeatures {
                        ForEach(info.featureColumns, id: \.self) { Text($0).font(.caption).foregroundStyle(Paper.ink2) }
                    }
                } else {
                    Text("Loading").font(.footnote).foregroundStyle(Paper.ink3)
                }
            }
            .padding(.top, 8)
        } label: {
            Text("Model and feature details").font(Paper.serif(16, .semibold)).foregroundStyle(Paper.ink)
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
                        Text("Paper (light)").tag("light")
                        Text("Dark").tag("dark")
                        Text("Match the phone").tag("system")
                    }
                }
                Section {
                    Picker("Alert me from", selection: $minSeverity) {
                        Text("Low severity").tag("LOW")
                        Text("Medium severity").tag("MEDIUM")
                        Text("High severity").tag("HIGH")
                        Text("Critical only").tag("CRITICAL")
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
                        LabeledContent("This phone", value: pairing.name)
                        LabeledContent("Certificate", value: String(pairing.fingerprint.prefix(16)) + "...")
                        Button("Forget this server", role: .destructive) { confirmForget = true }
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
                Button("Forget server", role: .destructive) {
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
