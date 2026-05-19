import Foundation

// MARK: - UpstreamProxyConfiguration

struct UpstreamProxyConfiguration: Sendable, Equatable, Codable {
    var isEnabled: Bool
    var proxies: [UpstreamProxyServer]
    var includeHosts: [String]
    var excludeHosts: [String]
    var bypassLocalhost: Bool
    var dnsOverSocks: Bool
    var listenerHost: String
    var listenerPort: Int

    static let disabled = UpstreamProxyConfiguration(
        isEnabled: false,
        proxies: [],
        includeHosts: [],
        excludeHosts: [],
        bypassLocalhost: true,
        dnsOverSocks: true,
        listenerHost: "127.0.0.1",
        listenerPort: 9_090
    )
}

// MARK: - UpstreamProxyServer

struct UpstreamProxyServer: Sendable, Equatable, Codable {
    var kind: UpstreamProxyKind
    var host: String
    var port: Int
    var username: String?
    var password: String?
    var pacScript: String?
    var pacURL: URL?

    init(
        kind: UpstreamProxyKind,
        host: String,
        port: Int,
        username: String? = nil,
        password: String? = nil,
        pacScript: String? = nil,
        pacURL: URL? = nil
    ) {
        self.kind = kind
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.pacScript = pacScript
        self.pacURL = pacURL
    }

    var proxyAuthorizationHeader: String? {
        guard let username, !username.isEmpty else { return nil }
        let password = password ?? ""
        let token = Data("\(username):\(password)".utf8).base64EncodedString()
        return "Basic \(token)"
    }
}

// MARK: - UpstreamProxyKind

enum UpstreamProxyKind: String, Sendable, Equatable, Codable {
    case http
    case https
    case socks5
    case pac
}

// MARK: - UpstreamRoute

enum UpstreamRoute: Sendable, Equatable {
    case direct(reason: UpstreamRouteReason)
    case httpProxy(UpstreamProxyServer, transportTLS: Bool)
    case socks5(UpstreamProxyServer)
    case failed(String)

    var summary: String {
        switch self {
        case .direct(let reason):
            switch reason {
            case .disabled:
                "Direct"
            case .bypassed:
                "Bypassed"
            case .pacDirect:
                "PAC Direct"
            }
        case .httpProxy(let server, let transportTLS):
            "\(transportTLS ? "HTTPS" : "HTTP") \(server.host):\(server.port)"
        case .socks5(let server):
            "SOCKS5 \(server.host):\(server.port)"
        case .failed(let message):
            "Failed: \(message)"
        }
    }

    var kindDisplay: String {
        switch self {
        case .direct(let reason):
            reason == .disabled ? "Direct" : "Bypassed"
        case .httpProxy(_, let transportTLS):
            transportTLS ? "HTTPS" : "HTTP"
        case .socks5:
            "SOCKS5"
        case .failed:
            "Failed"
        }
    }

    var requiresAbsoluteHTTPRequestURI: Bool {
        if case .httpProxy = self { return true }
        return false
    }

    var proxyAuthorizationHeader: String? {
        if case .httpProxy(let server, _) = self {
            return server.proxyAuthorizationHeader
        }
        return nil
    }
}

// MARK: - UpstreamRouteReason

enum UpstreamRouteReason: Sendable, Equatable {
    case disabled
    case bypassed
    case pacDirect
}

// MARK: - UpstreamProxyError

enum UpstreamProxyError: LocalizedError, Sendable, Equatable {
    case invalidConfiguration(String)
    case loopDetected(String)
    case noPACScript
    case pacReturnedNoRoutes
    case upstreamRejected(String)
    case unsupportedSOCKSAuthentication(UInt8)
    case socksFailure(UInt8)

    var errorDescription: String? {
        switch self {
        case .invalidConfiguration(let message):
            message
        case .loopDetected(let message):
            message
        case .noPACScript:
            "PAC upstream proxy is configured without a loaded PAC script."
        case .pacReturnedNoRoutes:
            "PAC returned no usable proxy routes."
        case .upstreamRejected(let message):
            message
        case .unsupportedSOCKSAuthentication(let method):
            "SOCKS5 upstream proxy selected unsupported authentication method 0x\(String(method, radix: 16))."
        case .socksFailure(let code):
            "SOCKS5 upstream proxy rejected CONNECT with reply code 0x\(String(code, radix: 16))."
        }
    }
}

// MARK: - UpstreamProxyState

final class UpstreamProxyState: @unchecked Sendable {
    init(configuration: UpstreamProxyConfiguration = .disabled) {
        self.configuration = configuration
    }

    func update(_ configuration: UpstreamProxyConfiguration) {
        lock.lock()
        self.configuration = configuration
        lock.unlock()
    }

    func routes(for host: String, port: Int, scheme: String?) throws -> [UpstreamRoute] {
        lock.lock()
        let snapshot = configuration
        lock.unlock()
        return try UpstreamRouter(configuration: snapshot).routes(for: host, port: port, scheme: scheme)
    }

    private let lock = NSLock()
    private var configuration: UpstreamProxyConfiguration
}

// MARK: - UpstreamRouter

struct UpstreamRouter: Sendable {
    let configuration: UpstreamProxyConfiguration

    func routes(for host: String, port: Int, scheme: String?) throws -> [UpstreamRoute] {
        guard configuration.isEnabled else {
            return [.direct(reason: .disabled)]
        }

        let normalizedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedHost.isEmpty else {
            return [.direct(reason: .bypassed)]
        }

        if configuration.bypassLocalhost, Self.isLocalhost(normalizedHost) {
            return [.direct(reason: .bypassed)]
        }

        if matchesAny(configuration.excludeHosts, host: normalizedHost, port: port) {
            return [.direct(reason: .bypassed)]
        }

        if !configuration.includeHosts.isEmpty,
           !matchesAny(configuration.includeHosts, host: normalizedHost, port: port)
        {
            return [.direct(reason: .bypassed)]
        }

        var routes: [UpstreamRoute] = []
        for proxy in configuration.proxies {
            try validateLoop(proxy)
            switch proxy.kind {
            case .http:
                routes.append(.httpProxy(proxy, transportTLS: false))
            case .https:
                routes.append(.httpProxy(proxy, transportTLS: true))
            case .socks5:
                routes.append(.socks5(proxy))
            case .pac:
                routes.append(contentsOf: try PACProxyResolver.routes(
                    for: normalizedHost,
                    port: port,
                    scheme: scheme,
                    proxy: proxy
                ))
            }
        }

        guard !routes.isEmpty else {
            return [.direct(reason: .disabled)]
        }
        return routes
    }

    private func validateLoop(_ proxy: UpstreamProxyServer) throws {
        let proxyHost = proxy.host.lowercased()
        let listenerHost = configuration.listenerHost.lowercased()
        let samePort = proxy.port == configuration.listenerPort
        let sameHost = proxyHost == listenerHost
            || (Self.isLocalhost(proxyHost) && Self.isLocalhost(listenerHost))
        if sameHost, samePort {
            throw UpstreamProxyError.loopDetected(
                "Upstream proxy \(proxy.host):\(proxy.port) points back to Rockxy's listener."
            )
        }
    }

    private func matchesAny(_ patterns: [String], host: String, port: Int) -> Bool {
        patterns.contains { pattern in
            Self.matches(pattern: pattern, host: host, port: port)
        }
    }

    static func matches(pattern: String, host: String, port: Int) -> Bool {
        let trimmed = pattern.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return false }
        let host = host.lowercased()
        let hostPort = "\(host):\(port)"
        let escaped = NSRegularExpression.escapedPattern(for: trimmed)
            .replacingOccurrences(of: "\\*", with: ".*")
        let regex = "^\(escaped)$"
        return host.range(of: regex, options: .regularExpression) != nil
            || hostPort.range(of: regex, options: .regularExpression) != nil
    }

    static func isLocalhost(_ host: String) -> Bool {
        let lowercased = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        return lowercased == "localhost"
            || lowercased == "127.0.0.1"
            || lowercased == "::1"
            || lowercased.hasPrefix("127.")
    }
}

// MARK: - PACProxyResolver

enum PACProxyResolver {
    static func routes(
        for host: String,
        port: Int,
        scheme: String?,
        proxy: UpstreamProxyServer
    ) throws -> [UpstreamRoute] {
        guard let script = proxy.pacScript, !script.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw UpstreamProxyError.noPACScript
        }

        let directive = extractReturnValue(from: script) ?? script
        let routes = try directive
            .split(separator: ";")
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .map { try route(from: $0, fallbackProxy: proxy) }

        guard !routes.isEmpty else {
            throw UpstreamProxyError.pacReturnedNoRoutes
        }
        return routes
    }

    private static func extractReturnValue(from script: String) -> String? {
        let pattern = #"return\s+['"]([^'"]+)['"]"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        let range = NSRange(script.startIndex ..< script.endIndex, in: script)
        guard let match = regex.firstMatch(in: script, range: range),
              let valueRange = Range(match.range(at: 1), in: script)
        else {
            return nil
        }
        return String(script[valueRange])
    }

    private static func route(from directive: String, fallbackProxy: UpstreamProxyServer) throws -> UpstreamRoute {
        let parts = directive.split(separator: " ", maxSplits: 1).map(String.init)
        let command = parts.first?.uppercased() ?? ""
        switch command {
        case "DIRECT":
            return .direct(reason: .pacDirect)
        case "PROXY":
            let server = try proxyServer(from: parts, kind: .http, fallbackProxy: fallbackProxy)
            return .httpProxy(server, transportTLS: false)
        case "HTTPS":
            let server = try proxyServer(from: parts, kind: .https, fallbackProxy: fallbackProxy)
            return .httpProxy(server, transportTLS: true)
        case "SOCKS", "SOCKS5":
            let server = try proxyServer(from: parts, kind: .socks5, fallbackProxy: fallbackProxy)
            return .socks5(server)
        default:
            throw UpstreamProxyError.invalidConfiguration("Unsupported PAC directive: \(directive)")
        }
    }

    private static func proxyServer(
        from parts: [String],
        kind: UpstreamProxyKind,
        fallbackProxy: UpstreamProxyServer
    ) throws -> UpstreamProxyServer {
        guard parts.count == 2 else {
            throw UpstreamProxyError.invalidConfiguration("PAC proxy directive is missing host and port.")
        }
        let endpoint = parts[1]
        let split = endpoint.split(separator: ":", maxSplits: 1).map(String.init)
        guard split.count == 2, let port = Int(split[1]), (1 ... 65_535).contains(port) else {
            throw UpstreamProxyError.invalidConfiguration("Invalid PAC proxy endpoint: \(endpoint)")
        }
        return UpstreamProxyServer(
            kind: kind,
            host: split[0],
            port: port,
            username: fallbackProxy.username,
            password: fallbackProxy.password
        )
    }
}
