import Crypto
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS
import os
import SwiftASN1
import X509

// Defines `TLSInterceptHandler`, which handles tls intercept flow in the proxy engine.

nonisolated(unsafe) private let tlsLogger = Logger(
    subsystem: RockxyIdentity.current.logSubsystem,
    category: "TLSInterceptHandler"
)

// MARK: - RecentFailureTracker

/// Tracks recent TLS handshake failures per host to suppress duplicate noise.
/// Thread-safe via NSLock; designed for use from NIO event loops.
final class RecentFailureTracker: @unchecked Sendable {
    // MARK: Lifecycle

    init(
        windowSeconds: Double = 30.0,
        nowProvider: @escaping @Sendable () -> DispatchTime = DispatchTime.now
    ) {
        self.windowSeconds = windowSeconds
        self.nowProvider = nowProvider
    }

    // MARK: Internal

    struct FailureInfo {
        var count: Int
        var lastFailed: DispatchTime
    }

    func recordFailure(host: String) -> FailureInfo {
        lock.lock()
        defer { lock.unlock() }
        let now = nowProvider()

        if let existing = failures[host] {
            let lastFailed = existing.lastFailed.uptimeNanoseconds
            let current = now.uptimeNanoseconds

            if current >= lastFailed {
                let elapsed = Double(current - lastFailed) / 1_000_000_000
                if elapsed < windowSeconds {
                    let updated = FailureInfo(count: existing.count + 1, lastFailed: now)
                    failures[host] = updated
                    return updated
                }
            } else {
                let updated = FailureInfo(count: existing.count + 1, lastFailed: now)
                failures[host] = updated
                return updated
            }
        }
        let fresh = FailureInfo(count: 1, lastFailed: now)
        failures[host] = fresh
        return fresh
    }

    // MARK: Private

    private var failures: [String: FailureInfo] = [:]
    private let lock = NSLock()
    private let windowSeconds: Double
    private let nowProvider: @Sendable () -> DispatchTime
}

// MARK: - TLSInterceptHandler

/// Performs HTTPS man-in-the-middle interception after a CONNECT tunnel is established.
///
/// When added to the pipeline, it requests a per-host TLS certificate from
/// `CertificateManager` (signed by Rockxy's root CA), then reconfigures the channel
/// pipeline: NIOSSLServerHandler (client-facing TLS) -> HTTP codecs ->
/// `HTTPSProxyRelayHandler` (forwards decrypted traffic to the real upstream over a
/// separate TLS connection).
///
/// If certificate generation fails (e.g., SSL pinned host), falls back to a raw TCP
/// tunnel via `RawTunnelHandler` so the connection still works — just without inspection.
final class TLSInterceptHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        host: String,
        port: Int,
        certificateManager: CertificateManager,
        ruleEngine: RuleEngine,
        scriptPluginManager: ScriptPluginManager? = nil,
        connectionLimiter: ConnectionLimiter,
        sslProxyingManager: SSLProxyingManager = .shared,
        customCertificateManager: CustomCertificateManager = .shared,
        upstreamProxyState: UpstreamProxyState = UpstreamProxyState(),
        clientSourcePort: UInt16? = nil,
        clientAppResolver: ClientAppResolver? = nil,
        tunnelStartedAt: DispatchTime = .now(),
        tunnelStartedDate: Date = Date(),
        onTransactionComplete: @escaping @Sendable (HTTPTransaction) -> Void,
        onBreakpointHit: (@Sendable (BreakpointRequestData) async -> (BreakpointDecision, BreakpointRequestData))? = nil
    ) {
        self.host = host
        self.port = port
        self.certificateManager = certificateManager
        self.ruleEngine = ruleEngine
        self.scriptPluginManager = scriptPluginManager
        self.connectionLimiter = connectionLimiter
        self.sslProxyingManager = sslProxyingManager
        self.customCertificateManager = customCertificateManager
        self.upstreamProxyState = upstreamProxyState
        self.clientSourcePort = clientSourcePort
        self.clientAppResolver = clientAppResolver
        self.tunnelStartedAt = tunnelStartedAt
        self.tunnelStartedDate = tunnelStartedDate
        self.onTransactionComplete = onTransactionComplete
        self.onBreakpointHit = onBreakpointHit
    }

    // MARK: Internal

    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    nonisolated static func makeTunnelTransaction(
        id: UUID = UUID(),
        host: String,
        port: Int,
        statusCode: Int,
        statusMessage: String,
        state: TransactionState,
        startedAt: Date = Date(),
        completedAt: Date? = nil,
        sourcePort: UInt16?,
        clientApp: String? = nil,
        clientAttribution: ClientAppAttribution? = nil,
        measuredDuration: TimeInterval? = nil,
        establishmentDuration: TimeInterval? = nil,
        isTLSFailure: Bool = false,
        upstreamRouteSummary: String? = nil,
        upstreamRouteKind: String? = nil
    )
        -> HTTPTransaction
    {
        let hostPart: String = if host.contains(":"), !host.hasPrefix("["), !host.hasSuffix("]") {
            "[\(host)]"
        } else {
            host
        }

        guard let tunnelURL = URL(string: "https://\(hostPart):\(port)") else {
            tlsLogger.warning("Failed to build CONNECT tunnel URL for host \(host, privacy: .public):\(port)")
            var fallbackComponents = URLComponents()
            fallbackComponents.scheme = "https"
            fallbackComponents.host = "invalid-tunnel.local"
            fallbackComponents.port = 443
            let fallbackURL = fallbackComponents.url ?? URL(fileURLWithPath: "/")
            return makeTunnelTransaction(
                id: id,
                host: fallbackURL.host ?? "invalid-tunnel.local",
                port: fallbackURL.port ?? 443,
                statusCode: statusCode,
                statusMessage: statusMessage,
                state: state,
                startedAt: startedAt,
                completedAt: completedAt,
                sourcePort: sourcePort,
                clientApp: clientApp,
                clientAttribution: clientAttribution,
                measuredDuration: measuredDuration,
                establishmentDuration: establishmentDuration,
                isTLSFailure: isTLSFailure,
                upstreamRouteSummary: upstreamRouteSummary,
                upstreamRouteKind: upstreamRouteKind
            )
        }
        let requestData = HTTPRequestData(
            method: "CONNECT",
            url: tunnelURL,
            httpVersion: "1.1",
            headers: [],
            body: nil,
            contentType: nil
        )
        let transaction = HTTPTransaction(
            id: id,
            timestamp: startedAt,
            request: requestData,
            response: HTTPResponseData(
                statusCode: statusCode,
                statusMessage: statusMessage,
                headers: []
            ),
            state: state
        )
        transaction.measuredDuration = measuredDuration
        transaction.startedAt = startedAt
        transaction.completedAt = completedAt
        transaction.establishmentDuration = establishmentDuration
        transaction.sourcePort = sourcePort
        transaction.clientApp = clientApp
        transaction.clientAttribution = clientAttribution
        transaction.isTLSFailure = isTLSFailure
        transaction.upstreamProxySummary = upstreamRouteSummary
        transaction.upstreamProxyKind = upstreamRouteKind
        return transaction
    }

    /// Central raw-tunnel wiring helper. Successful passthrough capture depends on this
    /// path completing and invoking `onSuccess`, so keep all raw CONNECT success setup in
    /// one place instead of reimplementing the relay chain in multiple handlers.
    nonisolated static func completeRawTunnelSetup(
        serverChannel: Channel,
        clientChannel: Channel,
        prepareClientChannel: EventLoopFuture<Void>,
        enableClientAutoRead: Bool = false,
        onSuccess: @escaping @Sendable () -> Void,
        onClose: @escaping @Sendable () -> Void = {},
        onFailure: @escaping @Sendable (Error) -> Void
    ) {
        let toClient = RawTunnelHandler(peerChannel: clientChannel, onClosed: onClose)
        let toServer = RawTunnelHandler(peerChannel: serverChannel, onClosed: onClose)

        serverChannel.pipeline.addHandler(toClient).flatMap {
            prepareClientChannel
        }.flatMap {
            clientChannel.pipeline.addHandler(toServer)
        }.flatMap {
            if enableClientAutoRead {
                return clientChannel.setOption(ChannelOptions.autoRead, value: true)
            }
            return clientChannel.eventLoop.makeSucceededVoidFuture()
        }.whenComplete { result in
            switch result {
            case .success:
                onSuccess()
            case let .failure(error):
                onFailure(error)
            }
        }
    }

    nonisolated func handlerAdded(context: ChannelHandlerContext) {
        setupTLSPipeline(context: context)
    }

    nonisolated func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        bufferedData.append(data)
    }

    nonisolated func errorCaught(context: ChannelHandlerContext, error: Error) {
        tlsLogger.error("TLS handler error for \(self.host): \(error.localizedDescription)")
        context.close(promise: nil)
    }

    // MARK: Private

    private let host: String
    private let port: Int
    private let certificateManager: CertificateManager
    private let ruleEngine: RuleEngine
    private let scriptPluginManager: ScriptPluginManager?
    private let connectionLimiter: ConnectionLimiter
    private let sslProxyingManager: SSLProxyingManager
    private let customCertificateManager: CustomCertificateManager
    private let upstreamProxyState: UpstreamProxyState
    private let clientSourcePort: UInt16?
    private let clientAppResolver: ClientAppResolver?
    private let tunnelStartedAt: DispatchTime
    private let tunnelStartedDate: Date
    private let onTransactionComplete: @Sendable (HTTPTransaction) -> Void
    private let onBreakpointHit: (@Sendable (BreakpointRequestData) async -> (
        BreakpointDecision,
        BreakpointRequestData
    ))?
    private var bufferedData: [NIOAny] = []

    /// Asynchronously fetches a per-host cert then rewires the pipeline on the event loop.
    /// The async cert generation (actor-isolated) is bridged to NIO via `makeFutureWithTask`.
    nonisolated private func setupTLSPipeline(context: ChannelHandlerContext) {
        let host = self.host
        let port = self.port

        if !sslProxyingManager.shouldIntercept(host) {
            tlsLogger.info("No SSL proxying rule for \(host), passing through as raw tunnel")
            setupRawTunnel(context: context, host: host, port: port)
            return
        }

        if sslProxyingManager.isAutoPassthrough(host) {
            tlsLogger.info("Auto-passthrough for \(host) (previous TLS rejection), raw tunnel")
            setupRawTunnel(context: context, host: host, port: port)
            return
        }

        let eventLoop = context.eventLoop
        let certManager = self.certificateManager
        let customCertificateManager = self.customCertificateManager
        let ruleEngine = self.ruleEngine
        let callback = self.onTransactionComplete
        let scriptPluginManager = self.scriptPluginManager
        let sourcePort = self.clientSourcePort
        let breakpointHit = self.onBreakpointHit
        let upstreamProxyState = self.upstreamProxyState

        let certFuture: EventLoopFuture<CustomTLSIdentity> =
            eventLoop.makeFutureWithTask {
                if let customIdentity = customCertificateManager.serverIdentity(for: host) {
                    return customIdentity
                }

                let result = try await certManager.certificateForHost(host)

                var serializer = DER.Serializer()
                try result.certificate.serialize(into: &serializer)
                let leafPEM = PEMDocument(type: "CERTIFICATE", derBytes: serializer.serializedBytes).pemString
                let keyPEM = result.privateKey.pemRepresentation

                return CustomTLSIdentity(certificateChainPEM: [leafPEM], privateKeyPEM: keyPEM)
            }

        certFuture.whenComplete { result in
            guard context.channel.isActive else {
                tlsLogger.debug("Client disconnected during cert generation for \(host)")
                return
            }
            switch result {
            case let .success(certResult):
                self.installTLSHandlers(
                    context: context,
                    identity: certResult,
                    host: host,
                    port: port,
                    ruleEngine: ruleEngine,
                    scriptPluginManager: scriptPluginManager,
                    callback: callback,
                    upstreamProxyState: upstreamProxyState,
                    breakpointHit: breakpointHit
                )
            case let .failure(error):
                tlsLogger.error("Certificate generation failed for \(host): \(error.localizedDescription)")
                self.setupRawTunnel(context: context, host: host, port: port)
            }
        }
    }

    nonisolated private func installTLSHandlers(
        context: ChannelHandlerContext,
        identity: CustomTLSIdentity,
        host: String,
        port: Int,
        ruleEngine: RuleEngine,
        scriptPluginManager: ScriptPluginManager?,
        callback: @escaping @Sendable (HTTPTransaction) -> Void,
        upstreamProxyState: UpstreamProxyState,
        breakpointHit: (@Sendable (BreakpointRequestData) async -> (BreakpointDecision, BreakpointRequestData))? = nil
    ) {
        guard !identity.certificateChainPEM.isEmpty, !identity.privateKeyPEM.isEmpty else {
            tlsLogger.warning("Empty certificate data for \(host), passing through raw bytes")
            setupRawTunnel(context: context, host: host, port: port)
            return
        }

        do {
            let sslContext = try NIOSSLContext(configuration: Self.makeServerTLSConfiguration(identity: identity))
            let sslHandler = NIOSSLServerHandler(context: sslContext)

            let postHandshake = PostHandshakeHandler(
                host: host,
                port: port,
                ruleEngine: ruleEngine,
                scriptPluginManager: scriptPluginManager,
                connectionLimiter: self.connectionLimiter,
                sslProxyingManager: self.sslProxyingManager,
                customCertificateManager: self.customCertificateManager,
                upstreamProxyState: upstreamProxyState,
                clientSourcePort: self.clientSourcePort,
                clientAppResolver: self.clientAppResolver,
                tunnelStartedAt: self.tunnelStartedAt,
                tunnelStartedDate: self.tunnelStartedDate,
                onTransactionComplete: callback,
                onBreakpointHit: breakpointHit
            )

            let detector = ProtocolDetectorHandler(
                sslHandler: sslHandler,
                host: host,
                port: port,
                postHandshake: postHandshake,
                connectionLimiter: self.connectionLimiter,
                upstreamProxyState: upstreamProxyState
            )

            let pipeline = context.pipeline
            let channel = context.channel

            // Remove self and leftover HTTP codecs, then build the detection pipeline:
            //   Head → ProtocolDetector → NIOSSLServerHandler → ConnectionLogger → PostHandshakeHandler → Tail
            // NIOSSLServerHandler is added FIRST (at .first), then ProtocolDetector is
            // added at .first BEFORE it. On first channelRead, the detector forwards TLS
            // data naturally via context.fireChannelRead to the next handler (NIOSSLServerHandler).
            // This avoids the broken channel.pipeline.fireChannelRead replay pattern.
            let buffered = self.bufferedData
            pipeline.removeHandler(context: context).flatMap {
                ProxyPipeline.removeHTTPServerPipeline(from: pipeline, on: channel.eventLoop)
            }.flatMap {
                pipeline.addHandler(sslHandler, position: .first)
            }.flatMap {
                pipeline.addHandler(detector, position: .first)
            }.flatMap {
                pipeline.addHandler(postHandshake)
            }.flatMap {
                channel.setOption(ChannelOptions.autoRead, value: true)
            }.whenComplete { result in
                switch result {
                case .success:
                    tlsLogger.debug("Protocol detector installed for \(host), waiting for first bytes")
                    if !buffered.isEmpty {
                        tlsLogger.debug("Replaying \(buffered.count) buffered read(s) for \(host)")
                        for data in buffered {
                            channel.pipeline.fireChannelRead(data)
                        }
                        channel.pipeline.fireChannelReadComplete()
                    }
                case let .failure(error):
                    tlsLogger.error("Pipeline setup failed for \(host): \(String(describing: error))")
                    channel.close(promise: nil)
                }
            }
        } catch {
            tlsLogger.error("SSL context creation failed for \(host): \(String(describing: error))")
            setupRawTunnel(context: context, host: host, port: port)
        }
    }

    nonisolated static func makeServerTLSConfiguration(identity: CustomTLSIdentity) throws -> TLSConfiguration {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: try identity.certificateSources,
            privateKey: try identity.privateKeySource
        )
        config.minimumTLSVersion = .tlsv12
        config.applicationProtocols = ["http/1.1"]
        return config
    }

    nonisolated private func setupRawTunnel(
        context: ChannelHandlerContext,
        host: String,
        port: Int
    ) {
        guard connectionLimiter.acquire(host: host, port: port) else {
            tlsLogger.warning("Connection limit reached for \(host):\(port), closing")
            context.close(promise: nil)
            return
        }
        let limiter = connectionLimiter

        let routes: [UpstreamRoute]
        do {
            routes = try upstreamProxyState.routes(for: host, port: port, scheme: "https")
        } catch {
            limiter.release(host: host, port: port)
            tlsLogger.error("Raw tunnel route resolution failed for \(host):\(port): \(error.localizedDescription)")
            onTransactionComplete(
                Self.makeTunnelTransaction(
                    host: host,
                    port: port,
                    statusCode: 502,
                    statusMessage: "Upstream Route Failed",
                    state: .failed,
                    startedAt: tunnelStartedDate,
                    completedAt: Date(),
                    sourcePort: clientSourcePort,
                    clientApp: clientAppResolver?.preferredApp(fallback: nil).name,
                    clientAttribution: clientAppResolver?.preferredApp(fallback: nil).attribution ?? .unresolved,
                    measuredDuration: tunnelElapsedDuration()
                )
            )
            context.close(promise: nil)
            return
        }

        UpstreamConnector.connectRawTunnel(
            on: context.eventLoop,
            targetHost: host,
            targetPort: port,
            routes: routes
        )
            .whenComplete { result in
                switch result {
                case let .success(connection):
                    let serverChannel = connection.channel
                    serverChannel.closeFuture.whenComplete { _ in
                        limiter.release(host: host, port: port)
                    }
                    let clientChannel = context.channel
                    let recorder = TunnelLifecycleRecorder(
                        host: host,
                        port: port,
                        startedAt: self.tunnelStartedDate,
                        startedMonotonic: self.tunnelStartedAt,
                        sourcePort: self.clientSourcePort,
                        clientAppResolver: self.clientAppResolver,
                        upstreamRoute: connection.route,
                        onTransactionComplete: self.onTransactionComplete
                    )
                    Self.completeRawTunnelSetup(
                        serverChannel: serverChannel,
                        clientChannel: clientChannel,
                        prepareClientChannel: context.pipeline.removeHandler(context: context),
                        enableClientAutoRead: true
                    ) {
                        recorder.recordEstablished()
                    } onClose: {
                        recorder.recordCompleted()
                    } onFailure: { error in
                        tlsLogger.error(
                            "Raw tunnel setup failed: \(error.localizedDescription)"
                        )
                        serverChannel.close(promise: nil)
                        context.channel.close(promise: nil)
                    }
                case let .failure(error):
                    limiter.release(host: host, port: port)
                    tlsLogger.error(
                        "Raw tunnel connection failed to \(host):\(port): \(error.localizedDescription)"
                    )
                    context.close(promise: nil)
                }
            }
    }

    nonisolated private func tunnelElapsedDuration() -> TimeInterval {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - tunnelStartedAt.uptimeNanoseconds
        return TimeInterval(elapsedNanos) / 1_000_000_000.0
    }
}

// MARK: - PostHandshakeHandler

/// Sits after NIOSSLServerHandler in the pipeline during TLS handshake. Listens for
/// `TLSUserEvent.handshakeCompleted`, then adds HTTP codecs and HTTPSProxyRelayHandler.
/// This prevents HTTP encoders from seeing raw TLS handshake bytes (which caused the
/// fatal "tried to decode as HTTPPart but found IOData" crash).
final class PostHandshakeHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        host: String,
        port: Int,
        ruleEngine: RuleEngine,
        scriptPluginManager: ScriptPluginManager?,
        connectionLimiter: ConnectionLimiter,
        sslProxyingManager: SSLProxyingManager,
        customCertificateManager: CustomCertificateManager = .shared,
        upstreamProxyState: UpstreamProxyState = UpstreamProxyState(),
        clientSourcePort: UInt16? = nil,
        clientAppResolver: ClientAppResolver? = nil,
        tunnelStartedAt: DispatchTime = .now(),
        tunnelStartedDate: Date = Date(),
        onTransactionComplete: @escaping @Sendable (HTTPTransaction) -> Void,
        onBreakpointHit: (@Sendable (BreakpointRequestData) async -> (BreakpointDecision, BreakpointRequestData))? = nil
    ) {
        self.host = host
        self.port = port
        self.ruleEngine = ruleEngine
        self.scriptPluginManager = scriptPluginManager
        self.connectionLimiter = connectionLimiter
        self.sslProxyingManager = sslProxyingManager
        self.customCertificateManager = customCertificateManager
        self.upstreamProxyState = upstreamProxyState
        self.clientSourcePort = clientSourcePort
        self.clientAppResolver = clientAppResolver
        self.tunnelStartedAt = tunnelStartedAt
        self.tunnelStartedDate = tunnelStartedDate
        self.onTransactionComplete = onTransactionComplete
        self.onBreakpointHit = onBreakpointHit
    }

    // MARK: Internal

    typealias InboundIn = ByteBuffer

    nonisolated func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is TLSUserEvent {
            guard !handshakeResolved else {
                return
            }
            handshakeResolved = true
            tlsLogger.info("TLS handshake completed for \(self.host) — adding HTTP codecs")

            let httpHandler = HTTPSProxyRelayHandler(
                host: host,
                port: port,
                ruleEngine: ruleEngine,
                scriptPluginManager: scriptPluginManager,
                connectionLimiter: connectionLimiter,
                customCertificateManager: customCertificateManager,
                upstreamProxyState: upstreamProxyState,
                clientSourcePort: clientSourcePort,
                clientAppResolver: clientAppResolver,
                onTransactionComplete: onTransactionComplete,
                onBreakpointHit: onBreakpointHit
            )

            let pipeline = context.pipeline
            pipeline.removeHandler(context: context).flatMap {
                pipeline.configureHTTPServerPipeline()
            }.flatMap {
                pipeline.addHandler(httpHandler)
            }.whenFailure { error in
                tlsLogger.error("Post-handshake pipeline setup failed for \(self.host): \(error.localizedDescription)")
                context.close(promise: nil)
            }
        } else {
            context.fireUserInboundEventTriggered(event)
        }
    }

    nonisolated func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }

    nonisolated func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard !handshakeResolved else {
            context.close(promise: nil)
            return
        }
        handshakeResolved = true
        let failInfo = Self.recentTLSFailures.recordFailure(host: host)
        let isCertRejection = Self.isCertificateRejection(error)

        if isCertRejection {
            sslProxyingManager.markHostForPassthrough(host)
        }

        if failInfo.count > 1 {
            tlsLogger.debug("Suppressing duplicate TLS failure for \(self.host) (count: \(failInfo.count))")
            context.close(promise: nil)
            return
        }

        if isCertRejection {
            tlsLogger.warning(
                "TLS cert rejected by client for \(self.host): \(String(describing: error)), marking auto-passthrough"
            )
            NotificationCenter.default.post(
                name: .tlsMitmRejected,
                object: nil,
                userInfo: ["host": host]
            )
        } else {
            tlsLogger.warning(
                "TLS error for \(self.host): \(String(describing: error)) — ambiguous, skipping passthrough"
            )
        }

        onTransactionComplete(
            TLSInterceptHandler.makeTunnelTransaction(
                host: host,
                port: port,
                statusCode: 0,
                statusMessage: "TLS Handshake Failed",
            state: .failed,
            startedAt: tunnelStartedDate,
            completedAt: Date(),
            sourcePort: clientSourcePort,
            clientApp: clientAppResolver?.preferredApp(fallback: nil).name,
            clientAttribution: clientAppResolver?.preferredApp(fallback: nil).attribution ?? .unresolved,
            measuredDuration: tunnelElapsedDuration(),
            isTLSFailure: true
        )
        )

        tearDownAndPassthrough(context: context)
    }

    nonisolated func makeSuccessfulTunnelTransaction(upstreamRoute: UpstreamRoute? = nil) -> HTTPTransaction {
        TLSInterceptHandler.makeTunnelTransaction(
            host: host,
            port: port,
            statusCode: 200,
            statusMessage: "Connection Established",
            state: .completed,
            startedAt: tunnelStartedDate,
            completedAt: Date(),
            sourcePort: clientSourcePort,
            clientApp: clientAppResolver?.preferredApp(fallback: nil).name,
            clientAttribution: clientAppResolver?.preferredApp(fallback: nil).attribution ?? .unresolved,
            measuredDuration: tunnelElapsedDuration(),
            establishmentDuration: tunnelElapsedDuration(),
            upstreamRouteSummary: upstreamRoute?.summary,
            upstreamRouteKind: upstreamRoute?.kindDisplay
        )
    }

    nonisolated func recordSuccessfulTunnel(upstreamRoute: UpstreamRoute? = nil) {
        onTransactionComplete(makeSuccessfulTunnelTransaction(upstreamRoute: upstreamRoute))
    }

    nonisolated func makeTunnelLifecycleRecorder(upstreamRoute: UpstreamRoute? = nil) -> TunnelLifecycleRecorder {
        TunnelLifecycleRecorder(
            host: host,
            port: port,
            startedAt: tunnelStartedDate,
            startedMonotonic: tunnelStartedAt,
            sourcePort: clientSourcePort,
            clientAppResolver: clientAppResolver,
            upstreamRoute: upstreamRoute,
            onTransactionComplete: onTransactionComplete
        )
    }

    // MARK: Private

    private static let recentTLSFailures = RecentFailureTracker()

    private let host: String
    private let port: Int
    private let ruleEngine: RuleEngine
    private let scriptPluginManager: ScriptPluginManager?
    private let connectionLimiter: ConnectionLimiter
    private let sslProxyingManager: SSLProxyingManager
    private let customCertificateManager: CustomCertificateManager
    private let upstreamProxyState: UpstreamProxyState
    private let clientSourcePort: UInt16?
    private let clientAppResolver: ClientAppResolver?
    private let tunnelStartedAt: DispatchTime
    private let tunnelStartedDate: Date
    private let onTransactionComplete: @Sendable (HTTPTransaction) -> Void
    private let onBreakpointHit: (@Sendable (BreakpointRequestData) async -> (
        BreakpointDecision,
        BreakpointRequestData
    ))?
    private var handshakeResolved = false

    /// Returns true if the error indicates the client rejected our generated certificate.
    /// BoringSSL errors are opaque strings, so we match against known alert patterns.
    private static func isCertificateRejection(_ error: Error) -> Bool {
        let desc = String(describing: error).lowercased()
        let certRejectionPatterns = [
            "certificate_unknown",
            "bad_certificate",
            "certificate_revoked",
            "certificate_expired",
            "unknown_ca",
            "certificate_verify_failed",
        ]
        return certRejectionPatterns.contains { desc.contains($0) }
    }

    nonisolated private func tunnelElapsedDuration() -> TimeInterval {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - tunnelStartedAt.uptimeNanoseconds
        return TimeInterval(elapsedNanos) / 1_000_000_000.0
    }

    /// Tear down failed TLS pipeline and attempt raw passthrough to the upstream server.
    /// After a client rejects the MITM certificate, the TLS session is dead but the
    /// underlying TCP socket may still be open. Setting up a raw tunnel allows Chrome
    /// to retry on the same or new connection without showing a privacy interstitial.
    nonisolated private func tearDownAndPassthrough(context: ChannelHandlerContext) {
        let host = self.host
        let port = self.port
        let channel = context.channel
        let limiter = self.connectionLimiter
        let upstreamProxyState = self.upstreamProxyState

        guard channel.isActive else {
            tlsLogger.debug("Channel already closed for \(host), skipping passthrough")
            return
        }

        guard limiter.acquire(host: host, port: port) else {
            tlsLogger.warning("Connection limit reached for \(host):\(port), closing")
            channel.close(promise: nil)
            return
        }

        let routes: [UpstreamRoute]
        do {
            routes = try upstreamProxyState.routes(for: host, port: port, scheme: "https")
        } catch {
            limiter.release(host: host, port: port)
            tlsLogger.warning(
                "Current-connection passthrough route resolution failed for \(host): \(error.localizedDescription), closing"
            )
            channel.close(promise: nil)
            return
        }

        let pipeline = context.pipeline

        pipeline.handler(type: NIOSSLServerHandler.self).flatMap { sslHandler in
            pipeline.removeHandler(sslHandler)
        }.flatMapError { _ in
            context.eventLoop.makeSucceededVoidFuture()
        }.flatMap {
            pipeline.removeHandler(context: context)
        }.flatMapError { _ in
            context.eventLoop.makeSucceededVoidFuture()
        }.flatMap {
            UpstreamConnector.connectRawTunnel(
                on: context.eventLoop,
                targetHost: host,
                targetPort: port,
                routes: routes
            )
        }.whenComplete { result in
            switch result {
            case let .success(connection):
                let serverChannel = connection.channel
                serverChannel.closeFuture.whenComplete { _ in
                    limiter.release(host: host, port: port)
                }
                TLSInterceptHandler.completeRawTunnelSetup(
                    serverChannel: serverChannel,
                    clientChannel: channel,
                    prepareClientChannel: channel.eventLoop.makeSucceededVoidFuture()
                ) {
                    tlsLogger.info(
                        "Current-connection passthrough established for \(host) via \(connection.route.summary, privacy: .public)"
                    )
                } onFailure: { _ in
                    serverChannel.close(promise: nil)
                    channel.close(promise: nil)
                }
            case let .failure(error):
                limiter.release(host: host, port: port)
                tlsLogger.warning(
                    "Current-connection passthrough failed for \(host): \(error.localizedDescription), closing"
                )
                channel.close(promise: nil)
            }
        }
    }
}

// MARK: - ProtocolDetectorHandler

/// Sits before NIOSSLServerHandler in the pipeline. Examines the first byte of
/// incoming data to determine if the client is speaking TLS. If yes, forwards
/// data naturally to the next handler (NIOSSLServerHandler) via context.fireChannelRead
/// and removes itself. If no, tears down TLS handlers and sets up a raw tunnel.
///
/// This forward-based approach avoids the broken channel.pipeline.fireChannelRead
/// replay pattern that causes WRONG_VERSION_NUMBER errors.
final class ProtocolDetectorHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        sslHandler: NIOSSLServerHandler,
        host: String,
        port: Int,
        postHandshake: PostHandshakeHandler,
        connectionLimiter: ConnectionLimiter,
        upstreamProxyState: UpstreamProxyState = UpstreamProxyState()
    ) {
        self.sslHandler = sslHandler
        self.host = host
        self.port = port
        self.postHandshake = postHandshake
        self.connectionLimiter = connectionLimiter
        self.upstreamProxyState = upstreamProxyState
    }

    // MARK: Internal

    typealias InboundIn = ByteBuffer

    nonisolated func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if detected {
            context.fireChannelRead(data)
            return
        }
        detected = true

        let buffer = unwrapInboundIn(data)
        guard let firstByte = buffer.getInteger(at: buffer.readerIndex, as: UInt8.self) else {
            context.close(promise: nil)
            return
        }

        // TLS record content types: 0x14=ChangeCipherSpec, 0x15=Alert,
        // 0x16=Handshake, 0x17=ApplicationData, 0x18=Heartbeat.
        // 0x80=SSLv2 ClientHello (legacy compatibility).
        let isTLS = (firstByte >= 0x14 && firstByte <= 0x18) || firstByte == 0x80

        if isTLS {
            tlsLogger.debug("TLS detected for \(self.host), forwarding to NIOSSLServerHandler")
            // Forward naturally to the next handler (NIOSSLServerHandler) in the pipeline.
            // No replay needed — data flows through the normal NIO path.
            context.fireChannelRead(data)
            // Remove ourselves so future reads go directly to NIOSSLServerHandler.
            context.pipeline.removeHandler(context: context, promise: nil)
        } else {
            tlsLogger
                .info(
                    "Non-TLS data (0x\(String(firstByte, radix: 16))) in CONNECT tunnel for \(self.host), falling back to raw tunnel"
                )
            tearDownForRawTunnel(context: context, firstData: data)
        }
    }

    nonisolated func errorCaught(context: ChannelHandlerContext, error: Error) {
        tlsLogger.warning("ProtocolDetector error for \(self.host): \(String(describing: error))")
        context.close(promise: nil)
    }

    // MARK: Private

    private let sslHandler: NIOSSLServerHandler
    private let host: String
    private let port: Int
    private let postHandshake: PostHandshakeHandler
    private let connectionLimiter: ConnectionLimiter
    private let upstreamProxyState: UpstreamProxyState
    private var detected = false

    /// Remove NIOSSLServerHandler and PostHandshakeHandler, then set up a raw TCP relay.
    nonisolated private func tearDownForRawTunnel(
        context: ChannelHandlerContext,
        firstData: NIOAny
    ) {
        let host = self.host
        let port = self.port
        let channel = context.channel
        let sslHandler = self.sslHandler
        let postHandshake = self.postHandshake
        let limiter = self.connectionLimiter
        let upstreamProxyState = self.upstreamProxyState

        guard limiter.acquire(host: host, port: port) else {
            tlsLogger.warning("Connection limit reached for \(host):\(port), closing")
            channel.close(promise: nil)
            return
        }

        let routes: [UpstreamRoute]
        do {
            routes = try upstreamProxyState.routes(for: host, port: port, scheme: "https")
        } catch {
            limiter.release(host: host, port: port)
            tlsLogger.error("Raw tunnel route resolution failed to \(host):\(port): \(String(describing: error))")
            channel.close(promise: nil)
            return
        }

        // Remove TLS-related handlers before setting up the raw tunnel
        let pipeline = context.pipeline
        pipeline.removeHandler(sslHandler).flatMapError { _ in
            context.eventLoop.makeSucceededVoidFuture()
        }.flatMap {
            pipeline.removeHandler(postHandshake)
        }.flatMapError { _ in
            context.eventLoop.makeSucceededVoidFuture()
        }.flatMap {
            pipeline.removeHandler(context: context)
        }.flatMap {
            UpstreamConnector.connectRawTunnel(
                on: context.eventLoop,
                targetHost: host,
                targetPort: port,
                routes: routes
            )
        }.whenComplete { result in
            switch result {
            case let .success(connection):
                let serverChannel = connection.channel
                serverChannel.closeFuture.whenComplete { _ in
                    limiter.release(host: host, port: port)
                }
                let recorder = self.postHandshake.makeTunnelLifecycleRecorder(upstreamRoute: connection.route)
                TLSInterceptHandler.completeRawTunnelSetup(
                    serverChannel: serverChannel,
                    clientChannel: channel,
                    prepareClientChannel: channel.eventLoop.makeSucceededVoidFuture()
                ) {
                    recorder.recordEstablished()
                    // Forward the first non-TLS data to the upstream once the raw tunnel is live.
                    channel.pipeline.fireChannelRead(firstData)
                    channel.pipeline.fireChannelReadComplete()
                } onClose: {
                    recorder.recordCompleted()
                } onFailure: { _ in
                    serverChannel.close(promise: nil)
                    channel.close(promise: nil)
                }
            case let .failure(error):
                limiter.release(host: host, port: port)
                tlsLogger.error("Raw tunnel connection failed to \(host):\(port): \(String(describing: error))")
                channel.close(promise: nil)
            }
        }
    }
}

// MARK: - TunnelLifecycleRecorder

final class TunnelLifecycleRecorder: @unchecked Sendable {
    init(
        host: String,
        port: Int,
        startedAt: Date,
        startedMonotonic: DispatchTime,
        sourcePort: UInt16?,
        clientAppResolver: ClientAppResolver?,
        upstreamRoute: UpstreamRoute?,
        onTransactionComplete: @escaping @Sendable (HTTPTransaction) -> Void
    ) {
        self.host = host
        self.port = port
        self.startedAt = startedAt
        self.startedMonotonic = startedMonotonic
        self.sourcePort = sourcePort
        self.clientAppResolver = clientAppResolver
        self.upstreamRoute = upstreamRoute
        self.onTransactionComplete = onTransactionComplete
    }

    func recordEstablished() {
        let shouldEmit = lock.withLock { () -> Bool in
            guard !didEmitEstablished else { return false }
            didEmitEstablished = true
            establishmentDuration = elapsedSinceStart()
            return true
        }
        guard shouldEmit else { return }

        onTransactionComplete(makeTransaction(state: .active, completedAt: nil))
    }

    func recordCompleted() {
        let shouldEmit = lock.withLock { () -> Bool in
            guard !didComplete else { return false }
            didComplete = true
            if establishmentDuration == nil {
                establishmentDuration = elapsedSinceStart()
            }
            return true
        }
        guard shouldEmit else { return }

        onTransactionComplete(makeTransaction(state: .completed, completedAt: Date()))
    }

    private let id = UUID()
    private let lock = NSLock()
    private let host: String
    private let port: Int
    private let startedAt: Date
    private let startedMonotonic: DispatchTime
    private let sourcePort: UInt16?
    private let clientAppResolver: ClientAppResolver?
    private let upstreamRoute: UpstreamRoute?
    private let onTransactionComplete: @Sendable (HTTPTransaction) -> Void
    private var didEmitEstablished = false
    private var didComplete = false
    private var establishmentDuration: TimeInterval?

    private func makeTransaction(state: TransactionState, completedAt: Date?) -> HTTPTransaction {
        let preferred = clientAppResolver?.preferredApp(fallback: nil)
        let measuredDuration = completedAt.map { $0.timeIntervalSince(startedAt) }
        return TLSInterceptHandler.makeTunnelTransaction(
            id: id,
            host: host,
            port: port,
            statusCode: 200,
            statusMessage: "Connection Established",
            state: state,
            startedAt: startedAt,
            completedAt: completedAt,
            sourcePort: sourcePort,
            clientApp: preferred?.name,
            clientAttribution: preferred?.attribution ?? .unresolved,
            measuredDuration: measuredDuration,
            establishmentDuration: lock.withLock { establishmentDuration },
            upstreamRouteSummary: upstreamRoute?.summary,
            upstreamRouteKind: upstreamRoute?.kindDisplay
        )
    }

    private func elapsedSinceStart() -> TimeInterval {
        let elapsedNanos = DispatchTime.now().uptimeNanoseconds - startedMonotonic.uptimeNanoseconds
        return TimeInterval(elapsedNanos) / 1_000_000_000.0
    }
}

// MARK: - RawTunnelHandler

/// Bidirectional byte-level relay between two channels. Used as a fallback when TLS
/// interception cannot be performed (cert generation failure, SSL pinning). Each side
/// of the tunnel gets its own RawTunnelHandler pointing at the peer channel.
final class RawTunnelHandler: ChannelInboundHandler, @unchecked Sendable {
    // MARK: Lifecycle

    init(peerChannel: Channel, onClosed: @escaping @Sendable () -> Void = {}) {
        self.peerChannel = peerChannel
        self.onClosed = onClosed
    }

    // MARK: Internal

    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    nonisolated func handlerAdded(context: ChannelHandlerContext) {
        resetIdleTimeout(context: context)
    }

    nonisolated func handlerRemoved(context: ChannelHandlerContext) {
        idleTimeout?.cancel()
        idleTimeout = nil
    }

    nonisolated func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        resetIdleTimeout(context: context)
        let buffer = unwrapInboundIn(data)
        peerChannel.writeAndFlush(NIOAny(buffer), promise: nil)
    }

    nonisolated func channelInactive(context: ChannelHandlerContext) {
        idleTimeout?.cancel()
        onClosed()
        peerChannel.close(promise: nil)
    }

    nonisolated func errorCaught(context: ChannelHandlerContext, error: Error) {
        idleTimeout?.cancel()
        onClosed()
        peerChannel.close(promise: nil)
        context.close(promise: nil)
    }

    // MARK: Private

    private static let idleTimeoutDuration: TimeAmount = .seconds(60)

    private let peerChannel: Channel
    private let onClosed: @Sendable () -> Void
    private var idleTimeout: Scheduled<Void>?

    nonisolated private func resetIdleTimeout(context: ChannelHandlerContext) {
        idleTimeout?.cancel()
        idleTimeout = context.eventLoop.scheduleTask(in: Self.idleTimeoutDuration) {
            tlsLogger.debug("Raw tunnel idle timeout, closing")
            context.close(promise: nil)
        }
    }
}
