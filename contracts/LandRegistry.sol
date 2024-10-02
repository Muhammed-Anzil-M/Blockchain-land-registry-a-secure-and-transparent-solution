// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LandRegistry {
    struct Land {
        address owner;
        string details;
        bool isApproved;
    }

    mapping(uint256 => Land) public lands;

    event LandAdded(uint256 indexed landId, address indexed owner, string details);
    event LandApproved(uint256 indexed landId);

    function addLand(uint256 landId, string memory details) public {
        lands[landId] = Land(msg.sender, details, false);
        emit LandAdded(landId, msg.sender, details);
    }

    function approveLand(uint256 landId) public {
        require(lands[landId].owner != address(0), "Land not found");
        require(!lands[landId].isApproved, "Land already approved");
        lands[landId].isApproved = true;
        emit LandApproved(landId);
    }
}
