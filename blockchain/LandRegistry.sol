// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LandRegistry {

    struct Land {
        uint256 landId;
        string landDetails;  // Details of the land
        address owner;       // Address of the landowner
        uint256 dateOfApproval; // Timestamp of approval
    }

    mapping(uint256 => Land) public lands; // Mapping of landId to Land struct
    uint256 public landCount = 0;          // Keeps track of the total land added

    address public govOfficer; // Government officer's address

    event LandApproved(uint256 landId, address indexed owner, uint256 dateOfApproval);

    modifier onlyGovOfficer() {
        require(msg.sender == govOfficer, "Only the government officer can approve land details.");
        _;
    }

    constructor() {
        govOfficer = msg.sender; // Assign contract deployer as the government officer
    }

    // Function to add approved land details to the blockchain
    function addApprovedLand(uint256 landId, string memory _landDetails, address _owner) public onlyGovOfficer {
        require(lands[landId].owner == address(0), "Land is already registered."); // Ensure land is not already added

        landCount++;
        lands[landCount] = Land(landId, _landDetails, _owner, block.timestamp); // Store the land details and the approval date
        emit LandApproved(landId, _owner, block.timestamp); // Emit an event to log the approval
    }

    // Function to get land details
    function getLandDetails(uint256 landId) public view returns (string memory, address, uint256) {
        Land memory land = lands[landId];
        return (land.landDetails, land.owner, land.dateOfApproval);
    }
}
