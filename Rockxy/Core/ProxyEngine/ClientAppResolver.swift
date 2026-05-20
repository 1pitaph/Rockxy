import Foundation

/// Per-client-connection process attribution. Resolution starts while the inbound
/// socket is still alive, then later transaction builders read the best known app.
final class ClientAppResolver: @unchecked Sendable {
    init(proxyPort: Int?) {
        self.proxyPort = proxyPort
    }

    func startResolving(sourcePort: UInt16?) {
        guard let sourcePort, let proxyPort else {
            setUnresolved()
            return
        }

        lock.lock()
        if didStart {
            lock.unlock()
            return
        }
        didStart = true
        self.sourcePort = sourcePort
        lock.unlock()

        Task { [weak self] in
            guard let self else { return }
            let portMap = await ProcessResolver.shared.resolveProcessesAsync(proxyPort: proxyPort)
            let appName = portMap[sourcePort]?.trimmingCharacters(in: .whitespacesAndNewlines)
            self.lock.withLock {
                if let appName, !appName.isEmpty {
                    self.resolvedAppName = appName
                    self.attribution = .process
                } else if self.attribution == nil {
                    self.attribution = .unresolved
                }
            }
        }
    }

    func preferredApp(fallback: String?) -> (name: String?, attribution: ClientAppAttribution?) {
        lock.lock()
        let resolved = resolvedAppName
        let resolvedAttribution = attribution
        lock.unlock()

        if let resolved, !resolved.isEmpty {
            return (resolved, .process)
        }

        let fallback = fallback?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let fallback, !fallback.isEmpty {
            return (fallback, .userAgent)
        }

        return (nil, resolvedAttribution ?? .unresolved)
    }

    func apply(to transaction: HTTPTransaction, fallback: String? = nil) {
        let preferred = preferredApp(fallback: fallback ?? transaction.clientApp)
        transaction.clientApp = preferred.name
        transaction.clientAttribution = preferred.attribution
    }

    private let lock = NSLock()
    private let proxyPort: Int?
    private var sourcePort: UInt16?
    private var didStart = false
    private var resolvedAppName: String?
    private var attribution: ClientAppAttribution?

    private func setUnresolved() {
        lock.withLock {
            attribution = .unresolved
        }
    }
}
