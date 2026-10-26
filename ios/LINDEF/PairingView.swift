import SwiftUI
import UIKit

/// First run: connect this phone to the LINDEF agent.
struct PairingView: View {
    @Environment(AppModel.self) private var model
    @State private var codeText = ""
    @State private var name = UIDevice.current.name
    @State private var error: String?
    @State private var working = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text("LINDEF")
                    .font(Paper.serif(22, .semibold))
                    .padding(.bottom, 10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .overlay(alignment: .bottom) { Rectangle().fill(Paper.ruleStrong).frame(height: 2) }

                Text("Connect to the server LINDEF protects")
                    .font(Paper.serif(32, .medium))
                    .foregroundStyle(Paper.ink)
                    .fixedSize(horizontal: false, vertical: true)

                Text("This phone talks to the LINDEF agent on that server directly. You pair once, from the desktop app.")
                    .foregroundStyle(Paper.ink2)

                VStack(alignment: .leading, spacing: 10) {
                    step(1, "On the desktop, open LINDEF and choose Pair a phone.")
                    step(2, "Scan the code with the iPhone Camera app. It opens LINDEF here.")
                    step(3, "Or copy the code on the desktop and paste it below.")
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Pairing code").font(.subheadline.weight(.semibold))
                    TextField("lindef://", text: $codeText, axis: .vertical)
                        .lineLimit(2...4)
                        .font(.footnote)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .padding(9)
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(Paper.rule))
                    Button("Paste from clipboard") {
                        if let text = UIPasteboard.general.string { codeText = text }
                    }
                    .font(.footnote)
                    .tint(Paper.accent)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Name for this phone").font(.subheadline.weight(.semibold))
                    TextField("My phone", text: $name)
                        .padding(9)
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(Paper.rule))
                    Text("Shown in the desktop's list of paired devices.").font(.footnote).foregroundStyle(Paper.ink3)
                }

                Button(working ? "Pairing" : "Pair with server") { Task { await pair() } }
                    .buttonStyle(PaperButtonStyle(primary: true))
                    .disabled(working || codeText.isEmpty)

                if let error {
                    Text(error).foregroundStyle(Paper.bad).font(.subheadline)
                }
            }
            .padding(20)
        }
        .foregroundStyle(Paper.ink)
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number).").font(Paper.serif(16, .semibold)).foregroundStyle(Paper.ink3)
            Text(text).foregroundStyle(Paper.ink2)
        }
    }

    private func pair() async {
        guard let code = PairingCode(codeText) else {
            error = "That is not a LINDEF pairing code. It starts with lindef:// and comes from the desktop's Pair a phone button."
            return
        }
        working = true
        defer { working = false }
        do {
            try await model.pair(code, name: name.isEmpty ? UIDevice.current.name : name)
        } catch {
            self.error = error.localizedDescription
        }
    }
}

/// Shown when a lindef:// link opens the app, so a link alone can never pair the phone.
struct ConfirmPairingView: View {
    let code: PairingCode
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = UIDevice.current.name
    @State private var error: String?
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Pair with this server?").font(Paper.serif(26, .medium))
            Text(model.pairing == nil
                 ? "Only continue if you just made this code on your LINDEF desktop."
                 : "This phone will switch from its current server to this one.")
                .foregroundStyle(Paper.ink2)
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                GridRow { Text("Server").foregroundStyle(Paper.ink3); Text("\(code.host):\(String(code.port))") }
                GridRow { Text("Certificate").foregroundStyle(Paper.ink3); Text(code.fingerprint.prefix(16) + "...").font(.footnote) }
            }
            .font(.subheadline)
            VStack(alignment: .leading, spacing: 6) {
                Text("Name for this phone").font(.subheadline.weight(.semibold))
                TextField("My phone", text: $name).padding(9).overlay(RoundedRectangle(cornerRadius: 3).stroke(Paper.rule))
            }
            HStack(spacing: 10) {
                Button("Cancel") { dismiss() }.buttonStyle(PaperButtonStyle())
                Button(working ? "Pairing" : "Pair") { Task { await pair() } }
                    .buttonStyle(PaperButtonStyle(primary: true)).disabled(working)
            }
            if let error { Text(error).foregroundStyle(Paper.bad).font(.subheadline) }
            Spacer()
        }
        .padding(22)
        .foregroundStyle(Paper.ink)
        .background(Paper.paper)
        .presentationDetents([.medium])
    }

    private func pair() async {
        working = true
        defer { working = false }
        do {
            try await model.pair(code, name: name.isEmpty ? UIDevice.current.name : name)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}
