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

extension CertificateSigningRequest {
    /// A representation of the additional attributes on a certificate signing request.
    ///
    /// CSR attributes are represented as an ASN.1 SET of key-value pairs, where each key
    /// may have 1 or more values. Attributes are defined in a wide range of specifications.
    ///
    /// ### Sequence and Collection Helpers
    ///
    /// ``CertificateSigningRequest/Attributes-swift.struct`` is conceptually a collection of
    /// ``CertificateSigningRequest/Attribute`` objects. The collection is unordered, and order
    /// is not preserved across modification.
    ///
    /// However, ``CertificateSigningRequest/Attributes-swift.struct`` is also conceptually a dictionary
    /// keyed by ``CertificateSigningRequest/Attribute/oid``. For that reason, in addition to the index-based subscript
    /// this type also offers ``subscript(oid:)`` to enable finding the attribute with a specific OID. This API also
    /// lets users replace the value of a specific attribute.
    ///
    /// ### Specific attribute helpers
    ///
    /// To make it easier to decode specific attributes, this type provides a number of helpers for known extension types:
    ///
    /// - ``extensionRequest``
    ///
    /// Users who add their own attribute types (see ``CertificateSigningRequest/Attribute`` for more) are encouraged to add their
    /// own helper getters for those types.
    public struct Attributes {
        @usableFromInline
        var _attributes: [Attribute]

        /// Produce a new Extensions container from an array of ``CertificateSigningRequest/Attribute``.
        ///
        /// - Parameter attributes: The base attributes.
        @inlinable
        public init(attributes: [Attribute]) {
            // TODO(cory): Police uniqueness
            self._attributes = attributes
        }

        /// Produce a new Attributes container from a collection of ``CertificateSigningRequest/Attribute``.
        ///
        /// - Parameter attributes: The base attributes.
        @inlinable
        public init<Elements>(_ attributes: Elements) where Elements: Sequence, Elements.Element == Attribute {
            self._attributes = Array(attributes)
        }
    }
}

extension CertificateSigningRequest.Attributes: Hashable { }

extension CertificateSigningRequest.Attributes: Sendable { }

// TODO: Tweak API surface here, this is more like a dictionary than an Array, and we
// need to forbid duplicate extensions. Consider backing this with OrderedDictionary.
extension CertificateSigningRequest.Attributes: RandomAccessCollection {
    @inlinable
    public init() {
        self._attributes = []
    }

    @inlinable
    public var startIndex: Int {
        self._attributes.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self._attributes.endIndex
    }

    @inlinable
    public subscript(position: Int) -> CertificateSigningRequest.Attribute {
        // TODO(cory): enforce uniqueness
        get {
            self._attributes[position]
        }
    }

    /// Insert a new ``CertificateSigningRequest/Attribute`` into this set of ``CertificateSigningRequest/Attributes-swift.struct``.
    ///
    /// - Parameter attribute: The ``CertificateSigningRequest/Attribute`` to insert.
    @inlinable
    public mutating func insert(_ ext: CertificateSigningRequest.Attribute) {
        // TODO(cory): enforce uniqueness
        self._attributes.append(ext)
    }

    /// Insert a sequence of new ``Certificate/Attribute``s into this set of ``Certificate/Attributes-swift.struct``.
    ///
    /// - Parameter extensions: The sequence of new ``Certificate/Attribute``s to insert.
    @inlinable
    public mutating func append<Extensions: Sequence>(contentsOf extensions: Extensions) where Extensions.Element == CertificateSigningRequest.Attribute {
        // TODO(cory): enforce uniqueness
        self._attributes.append(contentsOf: extensions)
    }
}

extension CertificateSigningRequest.Attributes: CustomStringConvertible {
    @inlinable
    public var description: String {
        return "Attributes([\(self._attributes.map { String(describing: $0) }.joined(separator: ", "))])"
    }
}

// MARK: Helpers for specific extensions
extension CertificateSigningRequest.Attributes {
    /// Look up a specific attribute by its OID.
    ///
    /// - Parameter oid: The OID to search for.
    @inlinable
    public subscript(oid oid: ASN1ObjectIdentifier) -> CertificateSigningRequest.Attribute? {
        get {
            return self.first(where: { $0.oid == oid })
        }
        set {
            if let newValue = newValue {
                precondition(oid == newValue.oid)
                if let currentAttributeIndex = self.firstIndex(where: { $0.oid == oid }) {
                    self._attributes[currentAttributeIndex] = newValue
                } else {
                    self._attributes.append(newValue)
                }
            } else if let currentAttributeIndex = self.firstIndex(where: { $0.oid == oid }) {
                self._attributes.remove(at: currentAttributeIndex)
            }
        }
    }
}
