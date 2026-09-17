// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @interface IVerifier
 * @notice Standard Groth16 / SNARK Zero-Knowledge Proof Verifier Interface.
 */
interface IVerifier {
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

/**
 * @title ZKIdentity (Zero-Knowledge Decentralized Identifier Registry)
 * @author Truxify Protocol Engineering
 * @notice W3C-compliant Zero-Knowledge Decentralized Identifier (ZK-DID) Registry Contract on Polygon.
 * Facilitates trustless, privacy-preserving identity authentication, credential revocation management,
 * and cryptographic ZK-proof verification binding identity owners with unique non-replayable nullifiers.
 */
contract ZKIdentity is Ownable {

    /// @notice Custom errors for precise gas-efficient error handling
    error DIDAlreadyExists(address identity);
    error DIDNotFound(address identity);
    error DIDRevoked(address identity);
    error CredentialAlreadyRevoked(bytes32 nullifierHash);
    error NullifierAlreadySpent(bytes32 nullifierHash);
    error InvalidVerifierAddress();
    error InvalidProofPayload();
    error ProofVerificationFailed();
    error TransferFailed();

    /**
     * @struct DIDDocument
     * @notice Stores metadata and cryptographic roots associated with a decentralized identifier.
     */
    struct DIDDocument {
        string didURI;
        bytes32 credentialMerkleRoot;
        bool isRevoked;
        uint256 registeredAt;
        uint256 lastUpdatedAt;
    }

    /// @notice Address of the deployed external ZK Verifier contract (e.g., Groth16 verifier)
    address public zkVerifier;

    /// @notice Mapping from identity owner address to their respective DID Document
    mapping(address => DIDDocument) public didRegistry;

    /// @notice Mapping tracking revoked credential nullifier hashes to prevent double-spending or replay
    mapping(bytes32 => bool) public revokedCredentials;

    /// @notice Mapping tracking spent nullifiers during authentication to ensure uniqueness
    mapping(bytes32 => bool) public spentNullifiers;

    /// @notice Emitted when a new decentralized identifier is registered on-chain
    event DIDRegistered(
        address indexed identity, 
        string didURI, 
        bytes32 merkleRoot,
        uint256 timestamp
    );

    /// @notice Emitted when a DID document is updated
    event DIDUpdated(
        address indexed identity, 
        string newDidURI, 
        bytes32 newMerkleRoot,
        uint256 timestamp
    );

    /// @notice Emitted when a DID or credential is revoked by the authority
    event CredentialRevoked(
        bytes32 indexed nullifierHash,
        address indexed identity,
        uint256 timestamp
    );

    /// @notice Emitted when a ZK proof is successfully verified and nullifier consumed
    event ZKProofVerified(
        address indexed identity,
        bytes32 indexed nullifierHash,
        uint256 timestamp
    );

    /// @notice Emitted when the ZK verifier contract address is updated by the owner
    event VerifierUpdated(
        address indexed oldVerifier,
        address indexed newVerifier,
        uint256 timestamp
    );

    /**
     * @notice Contract constructor initializing ownership and the ZK Verifier address
     * @param _zkVerifier Address of the external ZK verifier contract
     */
    constructor(address _zkVerifier) Ownable(msg.sender) {
        if (_zkVerifier == address(0)) revert InvalidVerifierAddress();
        zkVerifier = _zkVerifier;
    }

    /**
     * @notice Registers a new W3C-compliant decentralized identifier for the caller
     * @param _didURI Uniform Resource Identifier pointing to the off-chain DID document
     * @param _merkleRoot Merkle root committing to valid issued credentials
     */
    function registerDID(string calldata _didURI, bytes32 _merkleRoot) external {
        if (didRegistry[msg.sender].registeredAt != 0) revert DIDAlreadyExists(msg.sender);

        didRegistry[msg.sender] = DIDDocument({
            didURI: _didURI,
            credentialMerkleRoot: _merkleRoot,
            isRevoked: false,
            registeredAt: block.timestamp,
            lastUpdatedAt: block.timestamp
        });

        emit DIDRegistered(msg.sender, _didURI, _merkleRoot, block.timestamp);
    }

    /**
     * @notice Updates an existing DID document URI or credential Merkle root
     * @param _newDidURI Updated DID URI
     * @param _newMerkleRoot Updated credential Merkle root
     */
    function updateDID(string calldata _newDidURI, bytes32 _newMerkleRoot) external {
        DIDDocument storage doc = didRegistry[msg.sender];
        if (doc.registeredAt == 0) revert DIDNotFound(msg.sender);
        if (doc.isRevoked) revert DIDRevoked(msg.sender);

        doc.didURI = _newDidURI;
        doc.credentialMerkleRoot = _newMerkleRoot;
        doc.lastUpdatedAt = block.timestamp;

        emit DIDUpdated(msg.sender, _newDidURI, _newMerkleRoot, block.timestamp);
    }

    /**
     * @notice Revokes a credential nullifier preventing future authentication attempts
     * @param _nullifierHash Unique nullifier hash associated with the credential
     */
    function revokeCredential(bytes32 _nullifierHash) external onlyOwner {
        if (revokedCredentials[_nullifierHash]) revert CredentialAlreadyRevoked(_nullifierHash);

        revokedCredentials[_nullifierHash] = true;
        emit CredentialRevoked(_nullifierHash, msg.sender, block.timestamp);
    }

    /**
     * @notice Revokes an entire identity's registry entry
     * @param _identity Address of the identity to revoke
     */
    function revokeDID(address _identity) external onlyOwner {
        DIDDocument storage doc = didRegistry[_identity];
        if (doc.registeredAt == 0) revert DIDNotFound(_identity);

        doc.isRevoked = true;
        emit CredentialRevoked(bytes32(0), _identity, block.timestamp);
    }

    /**
     * @notice Verifies a Zero-Knowledge proof and ensures non-replayability via nullifiers (#14775)
     * @param _identity Address of the identity being authenticated
     * @param _zkProof Encoded ZK-SNARK proof bytes
     * @param _publicInputs Array of public inputs bound to the proof circuit
     * @param _nullifierHash Unique cryptographic nullifier preventing double-authentication
     */
    function verifyZkProof(
        address _identity,
        bytes calldata _zkProof,
        uint256[] calldata _publicInputs,
        bytes32 _nullifierHash
    ) external returns (bool) {
        DIDDocument memory doc = didRegistry[_identity];
        if (doc.registeredAt == 0 || doc.isRevoked) revert DIDNotFound(_identity);
        if (revokedCredentials[_nullifierHash]) revert CredentialAlreadyRevoked(_nullifierHash);
        if (spentNullifiers[_nullifierHash]) revert NullifierAlreadySpent(_nullifierHash);
        if (_zkProof.length == 0) revert InvalidProofPayload();

        // Perform rigorous on-chain cryptographic ZK verification via external verifier contract
        if (zkVerifier != address(0)) {
            bool isValid = IVerifier(zkVerifier).verifyProof(_zkProof, _publicInputs);
            if (!isValid) revert ProofVerificationFailed();
        }

        // Mark nullifier as spent to prevent replay attacks
        spentNullifiers[_nullifierHash] = true;

        emit ZKProofVerified(_identity, _nullifierHash, block.timestamp);
        return true;
    }

    /**
     * @notice Updates the external ZK Verifier contract address
     * @param _newVerifier New verifier contract address
     */
    function updateVerifier(address _newVerifier) external onlyOwner {
        if (_newVerifier == address(0)) revert InvalidVerifierAddress();
        address oldVerifier = zkVerifier;
        zkVerifier = _newVerifier;

        emit VerifierUpdated(oldVerifier, _newVerifier, block.timestamp);
    }

    /**
     * @notice Helper view function to retrieve full DID document details
     * @param _identity Identity address to query
     */
    function getDIDDocument(address _identity) external view returns (
        string memory didURI,
        bytes32 credentialMerkleRoot,
        bool isRevoked,
        uint256 registeredAt,
        uint256 lastUpdatedAt
    ) {
        DIDDocument memory doc = didRegistry[_identity];
        if (doc.registeredAt == 0) revert DIDNotFound(_identity);

        return (
            doc.didURI,
            doc.credentialMerkleRoot,
            doc.isRevoked,
            doc.registeredAt,
            doc.lastUpdatedAt
        );
    }
}
