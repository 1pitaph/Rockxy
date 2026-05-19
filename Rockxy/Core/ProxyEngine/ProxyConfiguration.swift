import Foundation

/// Configuration for the local proxy server. Controls which address and port the
/// server binds to.
struct ProxyConfiguration {
    static let `default` = ProxyConfiguration(
        port: 9_090,
        listenAddress: "127.0.0.1",
        listenIPv6: false,
        upstreamProxy: .disabled
    )

    let port: Int
    let listenAddress: String
    let listenIPv6: Bool
    let upstreamProxy: UpstreamProxyConfiguration

    init(
        port: Int,
        listenAddress: String,
        listenIPv6: Bool,
        upstreamProxy: UpstreamProxyConfiguration = .disabled
    ) {
        self.port = port
        self.listenAddress = listenAddress
        self.listenIPv6 = listenIPv6
        var upstreamProxy = upstreamProxy
        upstreamProxy.listenerHost = listenAddress
        upstreamProxy.listenerPort = port
        self.upstreamProxy = upstreamProxy
    }
}
