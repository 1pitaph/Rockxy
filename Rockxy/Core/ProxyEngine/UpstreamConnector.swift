import Darwin
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import os

nonisolated(unsafe) private let upstreamConnectorLogger = Logger(
    subsystem: RockxyIdentity.current.logSubsystem,
    category: "UpstreamConnector"
)

// MARK: - UpstreamConnectedChannel

struct UpstreamConnectedChannel {
    let channel: Channel
    let route: UpstreamRoute
    let requiresAbsoluteHTTPRequestURI: Bool
}

// MARK: - UpstreamConnector

enum UpstreamConnector {
    static func connectHTTP(
        on eventLoop: EventLoop,
        targetHost: String,
        targetPort: Int,
        useTLS: Bool,
        routes: [UpstreamRoute],
        customCertificateManager: CustomCertificateManager
    )
        -> EventLoopFuture<UpstreamConnectedChannel>
    {
        connectTryingRoutes(
            on: eventLoop,
            targetHost: targetHost,
            targetPort: targetPort,
            routes: routes
        ) { route in
            connectHTTP(
                on: eventLoop,
                targetHost: targetHost,
                targetPort: targetPort,
                useTLS: useTLS,
                route: route,
                customCertificateManager: customCertificateManager
            )
        }
    }

    static func connectRawTunnel(
        on eventLoop: EventLoop,
        targetHost: String,
        targetPort: Int,
        routes: [UpstreamRoute]
    )
        -> EventLoopFuture<UpstreamConnectedChannel>
    {
        connectTryingRoutes(
            on: eventLoop,
            targetHost: targetHost,
            targetPort: targetPort,
            routes: routes
        ) { route in
            connectRawTunnel(
                on: eventLoop,
                targetHost: targetHost,
                targetPort: targetPort,
                route: route
            )
        }
    }

    private static func connectTryingRoutes(
        on eventLoop: EventLoop,
        targetHost: String,
        targetPort: Int,
        routes: [UpstreamRoute],
        connector: @escaping (UpstreamRoute) -> EventLoopFuture<UpstreamConnectedChannel>
    )
        -> EventLoopFuture<UpstreamConnectedChannel>
    {
        var remaining = routes
        func attemptNext(_ lastError: Error? = nil) -> EventLoopFuture<UpstreamConnectedChannel> {
            guard !remaining.isEmpty else {
                return eventLoop.makeFailedFuture(
                    lastError ?? UpstreamProxyError.invalidConfiguration("No upstream routes available.")
                )
            }
            let route = remaining.removeFirst()
            if case .failed(let message) = route {
                return attemptNext(UpstreamProxyError.upstreamRejected(message))
            }
            return connector(route).flatMapError { error in
                upstreamConnectorLogger.warning(
                    "Upstream route \(route.summary, privacy: .public) failed for \(targetHost, privacy: .public):\(targetPort): \(error.localizedDescription, privacy: .public)"
                )
                return attemptNext(error)
            }
        }
        return attemptNext()
    }

    private static func connectHTTP(
        on eventLoop: EventLoop,
        targetHost: String,
        targetPort: Int,
        useTLS: Bool,
        route: UpstreamRoute,
        customCertificateManager: CustomCertificateManager
    )
        -> EventLoopFuture<UpstreamConnectedChannel>
    {
        switch route {
        case .direct:
            return connectDirect(
                on: eventLoop,
                host: targetHost,
                port: targetPort,
                useTLS: useTLS,
                tlsServerHostname: targetHost,
                customCertificateManager: customCertificateManager
            ).map {
                UpstreamConnectedChannel(
                    channel: $0,
                    route: route,
                    requiresAbsoluteHTTPRequestURI: false
                )
            }

        case .httpProxy(let server, let transportTLS):
            if useTLS {
                return connectViaHTTPProxyTunnel(
                    on: eventLoop,
                    server: server,
                    targetHost: targetHost,
                    targetPort: targetPort,
                    transportTLS: transportTLS
                ).flatMap { channel in
                    addTargetTLSAndHTTPHandlers(
                        to: channel,
                        serverHostname: targetHost,
                        customCertificateManager: customCertificateManager
                    )
                }.map {
                    UpstreamConnectedChannel(
                        channel: $0,
                        route: route,
                        requiresAbsoluteHTTPRequestURI: false
                    )
                }
            }
            return connectHTTPProxyForPlainHTTP(
                on: eventLoop,
                server: server,
                transportTLS: transportTLS
            ).map {
                UpstreamConnectedChannel(
                    channel: $0,
                    route: route,
                    requiresAbsoluteHTTPRequestURI: true
                )
            }

        case .socks5(let server):
            return connectViaSOCKS5(
                on: eventLoop,
                server: server,
                targetHost: targetHost,
                targetPort: targetPort
            ).flatMap { channel in
                if useTLS {
                    return addTargetTLSAndHTTPHandlers(
                        to: channel,
                        serverHostname: targetHost,
                        customCertificateManager: customCertificateManager
                    )
                }
                return channel.pipeline.addHTTPClientHandlers().map { channel }
            }.map {
                UpstreamConnectedChannel(
                    channel: $0,
                    route: route,
                    requiresAbsoluteHTTPRequestURI: false
                )
            }

        case .failed(let message):
            return eventLoop.makeFailedFuture(UpstreamProxyError.upstreamRejected(message))
        }
    }

    private static func connectRawTunnel(
        on eventLoop: EventLoop,
        targetHost: String,
        targetPort: Int,
        route: UpstreamRoute
    )
        -> EventLoopFuture<UpstreamConnectedChannel>
    {
        switch route {
        case .direct:
            return ClientBootstrap(group: eventLoop)
                .connectTimeout(.seconds(5))
                .connect(host: targetHost, port: targetPort)
                .map {
                    UpstreamConnectedChannel(
                        channel: $0,
                        route: route,
                        requiresAbsoluteHTTPRequestURI: false
                    )
                }

        case .httpProxy(let server, let transportTLS):
            return connectViaHTTPProxyTunnel(
                on: eventLoop,
                server: server,
                targetHost: targetHost,
                targetPort: targetPort,
                transportTLS: transportTLS
            ).map {
                UpstreamConnectedChannel(
                    channel: $0,
                    route: route,
                    requiresAbsoluteHTTPRequestURI: false
                )
            }

        case .socks5(let server):
            return connectViaSOCKS5(
                on: eventLoop,
                server: server,
                targetHost: targetHost,
                targetPort: targetPort
            ).map {
                UpstreamConnectedChannel(
                    channel: $0,
                    route: route,
                    requiresAbsoluteHTTPRequestURI: false
                )
            }

        case .failed(let message):
            return eventLoop.makeFailedFuture(UpstreamProxyError.upstreamRejected(message))
        }
    }

    private static func connectDirect(
        on eventLoop: EventLoop,
        host: String,
        port: Int,
        useTLS: Bool,
        tlsServerHostname: String,
        customCertificateManager: CustomCertificateManager
    )
        -> EventLoopFuture<Channel>
    {
        ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                if useTLS {
                    do {
                        let tlsConfig = try HTTPSProxyRelayHandler.makeClientTLSConfiguration(
                            clientIdentity: customCertificateManager.clientIdentity(for: tlsServerHostname)
                        )
                        let sslContext = try NIOSSLContext(configuration: tlsConfig)
                        let sslHandler = try NIOSSLClientHandler(
                            context: sslContext,
                            serverHostname: tlsServerHostname
                        )
                        return channel.pipeline.addHandler(sslHandler).flatMap {
                            channel.pipeline.addHTTPClientHandlers()
                        }
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
                return channel.pipeline.addHTTPClientHandlers()
            }
            .connect(host: host, port: port)
    }

    private static func connectHTTPProxyForPlainHTTP(
        on eventLoop: EventLoop,
        server: UpstreamProxyServer,
        transportTLS: Bool
    )
        -> EventLoopFuture<Channel>
    {
        connectToHTTPProxy(on: eventLoop, server: server, transportTLS: transportTLS)
            .flatMap { channel in
                channel.pipeline.addHTTPClientHandlers().map { channel }
            }
    }

    private static func connectViaHTTPProxyTunnel(
        on eventLoop: EventLoop,
        server: UpstreamProxyServer,
        targetHost: String,
        targetPort: Int,
        transportTLS: Bool
    )
        -> EventLoopFuture<Channel>
    {
        connectToHTTPProxy(on: eventLoop, server: server, transportTLS: transportTLS)
            .flatMap { channel in
                performHTTPConnectHandshake(
                    on: channel,
                    targetHost: targetHost,
                    targetPort: targetPort,
                    proxy: server
                ).map { channel }
            }
    }

    private static func connectToHTTPProxy(
        on eventLoop: EventLoop,
        server: UpstreamProxyServer,
        transportTLS: Bool
    )
        -> EventLoopFuture<Channel>
    {
        ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                guard transportTLS else {
                    return channel.eventLoop.makeSucceededVoidFuture()
                }
                do {
                    var tlsConfig = TLSConfiguration.makeClientConfiguration()
                    tlsConfig.applicationProtocols = ["http/1.1"]
                    let sslContext = try NIOSSLContext(configuration: tlsConfig)
                    let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: server.host)
                    return channel.pipeline.addHandler(sslHandler)
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
            }
            .connect(host: server.host, port: server.port)
    }

    private static func connectViaSOCKS5(
        on eventLoop: EventLoop,
        server: UpstreamProxyServer,
        targetHost: String,
        targetPort: Int
    )
        -> EventLoopFuture<Channel>
    {
        ClientBootstrap(group: eventLoop)
            .connectTimeout(.seconds(5))
            .connect(host: server.host, port: server.port)
            .flatMap { channel in
                performSOCKS5ConnectHandshake(
                    on: channel,
                    targetHost: targetHost,
                    targetPort: targetPort,
                    proxy: server
                ).map { channel }
            }
    }

    private static func addTargetTLSAndHTTPHandlers(
        to channel: Channel,
        serverHostname: String,
        customCertificateManager: CustomCertificateManager
    )
        -> EventLoopFuture<Channel>
    {
        do {
            let tlsConfig = try HTTPSProxyRelayHandler.makeClientTLSConfiguration(
                clientIdentity: customCertificateManager.clientIdentity(for: serverHostname)
            )
            let sslContext = try NIOSSLContext(configuration: tlsConfig)
            let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: serverHostname)
            return channel.pipeline.addHandler(sslHandler).flatMap {
                channel.pipeline.addHTTPClientHandlers()
            }.map { channel }
        } catch {
            return channel.eventLoop.makeFailedFuture(error)
        }
    }

    private static func performHTTPConnectHandshake(
        on channel: Channel,
        targetHost: String,
        targetPort: Int,
        proxy: UpstreamProxyServer
    )
        -> EventLoopFuture<Void>
    {
        let promise = channel.eventLoop.makePromise(of: Void.self)
        let handler = HTTPUpstreamConnectHandler(
            targetHost: targetHost,
            targetPort: targetPort,
            proxy: proxy,
            promise: promise
        )
        return channel.pipeline.addHandler(handler).flatMap {
            promise.futureResult
        }
    }

    private static func performSOCKS5ConnectHandshake(
        on channel: Channel,
        targetHost: String,
        targetPort: Int,
        proxy: UpstreamProxyServer
    )
        -> EventLoopFuture<Void>
    {
        let promise = channel.eventLoop.makePromise(of: Void.self)
        let handler = SOCKS5UpstreamConnectHandler(
            targetHost: targetHost,
            targetPort: targetPort,
            proxy: proxy,
            promise: promise
        )
        return channel.pipeline.addHandler(handler).flatMap {
            promise.futureResult
        }
    }
}

// MARK: - HTTPUpstreamConnectHandler

private final class HTTPUpstreamConnectHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    init(targetHost: String, targetPort: Int, proxy: UpstreamProxyServer, promise: EventLoopPromise<Void>) {
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.proxy = proxy
        self.promise = promise
    }

    func handlerAdded(context: ChannelHandlerContext) {
        var request = "CONNECT \(targetHost):\(targetPort) HTTP/1.1\r\nHost: \(targetHost):\(targetPort)\r\nProxy-Connection: Keep-Alive\r\n"
        if let authorization = proxyAuthorization {
            request += "Proxy-Authorization: \(authorization)\r\n"
        }
        request += "\r\n"
        var buffer = context.channel.allocator.buffer(capacity: request.utf8.count)
        buffer.writeString(request)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var chunk = unwrapInboundIn(data)
        received.writeBuffer(&chunk)
        guard let terminator = received.readableBytesView.firstRange(of: Array("\r\n\r\n".utf8)) else {
            if received.readableBytes > 16_384 {
                fail(context: context, error: UpstreamProxyError.upstreamRejected("Upstream CONNECT response header exceeded 16 KB."))
            }
            return
        }

        let headerLength = received.readableBytesView.distance(from: received.readableBytesView.startIndex, to: terminator.lowerBound) + 4
        guard let bytes = received.getBytes(at: received.readerIndex, length: headerLength),
              let header = String(bytes: bytes, encoding: .utf8)
        else {
            fail(context: context, error: UpstreamProxyError.upstreamRejected("Could not parse upstream CONNECT response."))
            return
        }

        let statusCode = parseStatusCode(from: header)
        guard (200 ..< 300).contains(statusCode) else {
            fail(context: context, error: UpstreamProxyError.upstreamRejected("Upstream proxy rejected CONNECT with status \(statusCode)."))
            return
        }

        received.moveReaderIndex(forwardBy: headerLength)
        let leftover = received.readSlice(length: received.readableBytes)
        context.pipeline.removeHandler(context: context).whenComplete { [promise] result in
            switch result {
            case .success:
                promise.succeed(())
                if var leftover, leftover.readableBytes > 0 {
                    context.fireChannelRead(self.wrapInboundOut(leftover))
                    context.fireChannelReadComplete()
                }
            case .failure(let error):
                promise.fail(error)
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(context: context, error: error)
    }

    private let targetHost: String
    private let targetPort: Int
    private let proxy: UpstreamProxyServer
    private let promise: EventLoopPromise<Void>
    private var received = ByteBufferAllocator().buffer(capacity: 0)

    private var proxyAuthorization: String? {
        proxy.proxyAuthorizationHeader
    }

    private func parseStatusCode(from header: String) -> Int {
        let firstLine = header.components(separatedBy: "\r\n").first ?? ""
        let parts = firstLine.split(separator: " ")
        guard parts.count >= 2, let code = Int(parts[1]) else {
            return 0
        }
        return code
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
        context.close(promise: nil)
    }
}

// MARK: - SOCKS5UpstreamConnectHandler

private final class SOCKS5UpstreamConnectHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    init(targetHost: String, targetPort: Int, proxy: UpstreamProxyServer, promise: EventLoopPromise<Void>) {
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.proxy = proxy
        self.promise = promise
    }

    func handlerAdded(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: 4)
        if hasCredentials {
            buffer.writeBytes([0x05, 0x02, 0x00, 0x02])
        } else {
            buffer.writeBytes([0x05, 0x01, 0x00])
        }
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var chunk = unwrapInboundIn(data)
        received.writeBuffer(&chunk)
        process(context: context)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        fail(context: context, error: error)
    }

    private enum State {
        case greeting
        case auth
        case connect
        case complete
    }

    private let targetHost: String
    private let targetPort: Int
    private let proxy: UpstreamProxyServer
    private let promise: EventLoopPromise<Void>
    private var received = ByteBufferAllocator().buffer(capacity: 0)
    private var state: State = .greeting

    private var hasCredentials: Bool {
        !(proxy.username ?? "").isEmpty
    }

    private func process(context: ChannelHandlerContext) {
        while true {
            switch state {
            case .greeting:
                guard received.readableBytes >= 2 else { return }
                let version = received.readInteger(as: UInt8.self) ?? 0
                let method = received.readInteger(as: UInt8.self) ?? 0xff
                guard version == 0x05 else {
                    fail(context: context, error: UpstreamProxyError.socksFailure(version))
                    return
                }
                switch method {
                case 0x00:
                    sendConnectRequest(context: context)
                    state = .connect
                case 0x02 where hasCredentials:
                    sendAuthentication(context: context)
                    state = .auth
                default:
                    fail(context: context, error: UpstreamProxyError.unsupportedSOCKSAuthentication(method))
                    return
                }

            case .auth:
                guard received.readableBytes >= 2 else { return }
                _ = received.readInteger(as: UInt8.self) ?? 0
                let status = received.readInteger(as: UInt8.self) ?? 0xff
                guard status == 0x00 else {
                    fail(context: context, error: UpstreamProxyError.socksFailure(status))
                    return
                }
                sendConnectRequest(context: context)
                state = .connect

            case .connect:
                guard received.readableBytes >= 5 else { return }
                let startIndex = received.readerIndex
                let version = received.readInteger(as: UInt8.self) ?? 0
                let reply = received.readInteger(as: UInt8.self) ?? 0
                _ = received.readInteger(as: UInt8.self) as UInt8? // reserved
                let addressType = received.readInteger(as: UInt8.self) ?? 0
                guard version == 0x05, reply == 0x00 else {
                    fail(context: context, error: UpstreamProxyError.socksFailure(reply))
                    return
                }
                let addressBytes: Int
                switch addressType {
                case 0x01:
                    addressBytes = 4
                case 0x03:
                    guard let length = received.getInteger(at: received.readerIndex, as: UInt8.self) else {
                        received.moveReaderIndex(to: startIndex)
                        return
                    }
                    addressBytes = 1 + Int(length)
                case 0x04:
                    addressBytes = 16
                default:
                    fail(context: context, error: UpstreamProxyError.socksFailure(addressType))
                    return
                }
                guard received.readableBytes >= addressBytes + 2 else {
                    received.moveReaderIndex(to: startIndex)
                    return
                }
                received.moveReaderIndex(forwardBy: addressBytes + 2)
                state = .complete
                context.pipeline.removeHandler(context: context).whenComplete { [promise] result in
                    switch result {
                    case .success:
                        promise.succeed(())
                    case .failure(let error):
                        promise.fail(error)
                    }
                }
                return

            case .complete:
                return
            }
        }
    }

    private func sendAuthentication(context: ChannelHandlerContext) {
        let username = proxy.username ?? ""
        let password = proxy.password ?? ""
        var buffer = context.channel.allocator.buffer(capacity: username.utf8.count + password.utf8.count + 3)
        buffer.writeInteger(UInt8(0x01))
        buffer.writeInteger(UInt8(min(username.utf8.count, 255)))
        buffer.writeBytes(username.utf8.prefix(255))
        buffer.writeInteger(UInt8(min(password.utf8.count, 255)))
        buffer.writeBytes(password.utf8.prefix(255))
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func sendConnectRequest(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: 32 + targetHost.utf8.count)
        buffer.writeBytes([0x05, 0x01, 0x00])
        if let ipv4 = Self.ipv4Bytes(targetHost) {
            buffer.writeInteger(UInt8(0x01))
            buffer.writeBytes(ipv4)
        } else if let ipv6 = Self.ipv6Bytes(targetHost) {
            buffer.writeInteger(UInt8(0x04))
            buffer.writeBytes(ipv6)
        } else {
            let domain = Array(targetHost.utf8.prefix(255))
            buffer.writeInteger(UInt8(0x03))
            buffer.writeInteger(UInt8(domain.count))
            buffer.writeBytes(domain)
        }
        buffer.writeInteger(UInt16(targetPort), endianness: .big)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
        context.close(promise: nil)
    }

    private static func ipv4Bytes(_ host: String) -> [UInt8]? {
        var addr = in_addr()
        guard inet_pton(AF_INET, host, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: addr.s_addr.bigEndian, Array.init)
    }

    private static func ipv6Bytes(_ host: String) -> [UInt8]? {
        let stripped = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var addr = in6_addr()
        guard inet_pton(AF_INET6, stripped, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: addr, Array.init)
    }
}

private extension Collection where Element == UInt8 {
    func firstRange(of needle: [UInt8]) -> Range<Index>? {
        guard !needle.isEmpty, count >= needle.count else { return nil }
        var index = startIndex
        while index != endIndex {
            var cursor = index
            var matched = true
            for byte in needle {
                if cursor == endIndex || self[cursor] != byte {
                    matched = false
                    break
                }
                formIndex(after: &cursor)
            }
            if matched {
                return index ..< cursor
            }
            formIndex(after: &index)
        }
        return nil
    }
}
