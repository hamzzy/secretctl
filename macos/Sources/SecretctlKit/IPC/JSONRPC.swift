import Foundation

struct RpcRequest: Encodable {
    let jsonrpc = "2.0"
    let id: String
    let method: String
    let params: JSONValue?
}

struct RpcResponse: Decodable {
    let id: JSONValue?
    let result: JSONValue?
    let error: RpcErrorPayload?
}

struct RpcErrorPayload: Decodable {
    let code: Int
    let message: String
}

/// An error the broker itself returned.
///
/// The numeric code is preserved rather than flattened into a message, because
/// the UI shows plain language in the primary surface and the raw code only
/// behind "technical details".
public struct BrokerError: Error, Equatable {
    public let code: Int
    public let message: String

    public init(code: Int, message: String) {
        self.code = code
        self.message = message
    }
}

/// A minimal dynamic JSON value, used for request params and for handing
/// results to `Decodable` models.
public enum JSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Int.self) { self = .int(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else if let value = try? container.decode([String: JSONValue].self) { self = .object(value) }
        else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// Integers must stay integers on the wire. `serde` refuses to read `50.0`
    /// into a `u32`, so encoding every number as a `Double` would make any
    /// call carrying a count or a TTL fail with an opaque parameter error.
    public static func integer(_ value: Int) -> JSONValue { .int(value) }

    /// Encode raw bytes the way `serde` expects a Rust `Vec<u8>`: a JSON array
    /// of numbers, not a base64 string.
    public static func bytes(_ data: Data) -> JSONValue {
        .array(data.map { .int(Int($0)) })
    }
}
