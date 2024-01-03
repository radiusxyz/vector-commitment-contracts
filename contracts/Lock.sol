pragma solidity ^0.8.9;

contract Lock {
    uint public unlockTime;
    address payable public owner;

    event Withdrawal(uint amount, uint when);

    constructor(uint _unlockTime) payable {
        require(
            block.timestamp < _unlockTime,
            "Unlock time should be in the future"
        );

        unlockTime = _unlockTime;
        owner = payable(msg.sender);
    }

    function withdraw() public {
        require(block.timestamp >= unlockTime, "You can't withdraw yet");
        require(msg.sender == owner, "You aren't the owner");

        emit Withdrawal(address(this).balance, block.timestamp);

        owner.transfer(address(this).balance);
    }
}

library Pairing {
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
     * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
     */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
     * @return r the sum of two points of G1
     */
    function plus(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
        }

        require(success, "pairing-add-failed");
    }

    /*
     * @return r the product of a point on G1 and a scalar, i.e.
     * p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
     * points p.
     */
    function scalar_mul(
        G1Point memory p,
        uint256 s
    ) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
        }
        require(success, "pairing-mul-failed");
    }
}

contract Verifier {
    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G2Point g_com;
        Pairing.G2Point g_proof;
        Pairing.G1Point g_1;
        Pairing.G1Point g_1_tmp;
        // Pairing.G2Point g_2_pow_N;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    // Output the verification result: (e(aG1, bG2) * (cG1, dG2) * e(eG1, fG2) == 1)
    function verifyProof() public view returns (bytes memory) {
        // commitment C
        uint256 aG1_x = 3010198690406615200373504922352659861758983907867017329644089018310584441462;
        uint256 aG1_y = 17861058253836152797273815394432013122766662423622084931972383889279925210507;
        // g_2^{N+1-i}
        uint256 bG2_x1 = 2725019753478801796453339367788033689375851816420509565303521482350756874229;
        uint256 bG2_x2 = 7273165102799931111715871471550377909735733521218303035754523677688038059653;
        uint256 bG2_y1 = 2512659008974376214222774206987427162027254181373325676825515531566330959255;
        uint256 bG2_y2 = 957874124722006818841961785324909313781880061366718538693995380805373202866;
        // proof-1
        uint256 cG1_x = 4503322228978077916651710446042370109107355802721800704639343137502100212473;
        uint256 cG1_y = 6132642251294427119375180147349983541569387941788025780665104001559216576968;
        // g_2
        uint256 dG2_x1 = 18029695676650738226693292988307914797657423701064905010927197838374790804409;
        uint256 dG2_x2 = 14583779054894525174450323658765874724019480979794335525732096752006891875705;
        uint256 dG2_y1 = 2140229616977736810657479771656733941598412651537078903776637920509952744750;
        uint256 dG2_y2 = 11474861747383700316476719153975578001603231366361248090558603872215261634898;

        // (g_1^\alpha)-1
        uint256 eG1_x = 0;
        uint256 eG1_y = 0;

        // g_2^{\alpha^N}
        uint256 fG2_x1 = 18029695676650738226693292988307914797657423701064905010927197838374790804409;
        uint256 fG2_x2 = 14583779054894525174450323658765874724019480979794335525732096752006891875705;
        uint256 fG2_y1 = 2140229616977736810657479771656733941598412651537078903776637920509952744750;
        uint256 fG2_y2 = 11474861747383700316476719153975578001603231366361248090558603872215261634898;

        bytes memory points = abi.encode(
            aG1_x,
            aG1_y,
            bG2_x2,
            bG2_x1,
            bG2_y2,
            bG2_y1,
            cG1_x,
            cG1_y,
            dG2_x2,
            dG2_x1,
            dG2_y2,
            dG2_y1,
            eG1_x,
            eG1_y,
            fG2_x2,
            fG2_x1,
            fG2_y2,
            fG2_y1
        );
        return testPairingCheck(points);
    }

    function testPairingCheck(
        bytes memory input
    ) public view returns (bytes memory) {
        if (input.length % 192 != 0) revert("Points must be a multiple of 6");
        (bool success, bytes memory data) = address(0x08).staticcall(input);
        if (success) return data;
        revert("Wrong pairing");
    }
}
