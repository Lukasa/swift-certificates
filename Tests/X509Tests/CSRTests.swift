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

import XCTest
import Crypto
import SwiftASN1
@testable import X509

final class CSRTests: XCTestCase {
    func testSimpleRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName {
            CommonName("Hello")
        }
        let extensions = try Certificate.Extensions {
            SubjectAlternativeNames([.dnsName("example.com")])
        }
        let extensionRequest = ExtensionRequest(extensions: extensions)
        let attributes = CertificateSigningRequest.Attributes(
            [.init(extensionRequest)]
        )
        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: name,
            privateKey: .init(key),
            attributes: attributes,
            signatureAlgorithm: .ecdsaWithSHA256
        )

        let bytes = try DER.Serializer.serialized(element: csr)
        let parsed = try CertificateSigningRequest(derEncoded: bytes)

        XCTAssertEqual(parsed, csr)
    }
}
