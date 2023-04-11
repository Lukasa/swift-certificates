//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

public struct ExtensionRequest: Hashable, Sendable {
    public var extensions: Certificate.Extensions

    @inlinable
    public init(extensions: Certificate.Extensions) {
        self.extensions = extensions
    }
}

extension CertificateSigningRequest.Attribute {
    @inlinable
    public init(_ extensionRequest: ExtensionRequest) {
        self.init(oid: .CSRAttributes.extensionRequest, values: [try! ASN1Any(erasing: ExtensionRequestAttribute(extensionRequest))])
    }
}

@usableFromInline
struct ExtensionRequestAttribute: Hashable, Sendable, DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var extensions: Certificate.Extensions

    @inlinable
    init(_ extensionRequest: ExtensionRequest) {
        self.extensions = extensionRequest.extensions
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.extensions = try Certificate.Extensions(
            DER.sequence(
                of: Certificate.Extension.self,
                identifier: identifier,
                rootNode: rootNode
            )
        )
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(self.extensions, identifier: identifier)
    }
}
