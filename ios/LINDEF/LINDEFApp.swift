import SwiftUI
import UserNotifications

@main
struct LINDEFApp: App {
    @State private var model = AppModel()
    @AppStorage("appearance") private var appearance = "light"
    @Environment(\.scenePhase) private var scenePhase

    init() {
        UNUserNotificationCenter.current().delegate = NotificationPresenter.shared
        BackgroundRefresh.register()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .preferredColorScheme(appearance == "dark" ? .dark : appearance == "light" ? .light : nil)
                .onOpenURL { model.received(url: $0) }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active: model.startPolling()
            case .background:
                model.stopPolling()
                BackgroundRefresh.schedule()
            default: break
            }
        }
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        ZStack {
            Paper.paper.ignoresSafeArea()
            if model.pairing == nil {
                PairingView()
            } else {
                DashboardView()
            }
        }
        .sheet(item: $model.pendingCode) { code in
            ConfirmPairingView(code: code)
        }
    }
}
