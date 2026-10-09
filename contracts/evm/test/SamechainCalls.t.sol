// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.34;
import {SamechainAuthority} from "../src/SamechainAuthority.sol";
import {SamechainCodec} from "../src/SamechainCodec.sol";
import {SamechainCallVectors} from "./fixtures/SamechainCallVectors.sol";
import {SamechainNativeVectors} from "./fixtures/SamechainNativeVectors.sol";
import {SamechainFill2Vectors} from "./fixtures/SamechainFill2Vectors.sol";
interface SamechainCallsVm { function getCode(string calldata) external view returns(bytes memory); }
// ABI/codec only: no verifier, no deposit admission or financial effects.
contract SamechainCallsHarness {
    function decode(bytes calldata data) external view returns(bytes32 packetHash,bytes32 proofAHash,bytes32 proofBHash,uint8 role,uint8 action,bytes memory journalA,bytes memory journalB) {
        bytes4 selector=bytes4(data[:4]);bytes memory packet;bytes memory proof;bytes memory proofB;
        if(selector==SamechainAuthority.create.selector){
            (packet,proof)=abi.decode(data[4:],(bytes,bytes));
            require(keccak256(data)==keccak256(abi.encodeWithSelector(selector,packet,proof)),"canonical creation ABI");
            journalA=this.creationJournal(packet);
        }else if(selector==SamechainAuthority.fill.selector){
            (packet,proof,proofB)=abi.decode(data[4:],(bytes,bytes,bytes));
            require(keccak256(data)==keccak256(abi.encodeWithSelector(selector,packet,proof,proofB)),"canonical fill ABI");
            (journalA,journalB)=this.fillJournals(packet);
        }else if(selector==SamechainAuthority.cancelOrExit.selector){
            (packet,role,action,proof)=abi.decode(data[4:],(bytes,uint8,uint8,bytes));
            require(keccak256(data)==keccak256(abi.encodeWithSelector(selector,packet,role,action,proof)),"canonical single ABI");
            journalA=this.singleJournal(packet,role,action);
        }else if(selector==SamechainAuthority.withdraw.selector){
            (packet,proof)=abi.decode(data[4:],(bytes,bytes));
            require(keccak256(data)==keccak256(abi.encodeWithSelector(selector,packet,proof)),"canonical withdrawal ABI");
            journalA=this.withdrawalJournal(packet);
        }else{revert("unknown actual authority ABI");}
        return(sha256(packet),sha256(proof),sha256(proofB),role,action,journalA,journalB);
    }
    function creationJournal(bytes calldata packet) external pure returns(bytes memory){return SamechainCodec.creationJournal(SamechainCodec.decodeCreation(packet));}
    function fillJournals(bytes calldata packet) external pure returns(bytes memory,bytes memory){SamechainCodec.Packet memory value=SamechainCodec.decodeFill(packet);return(SamechainCodec.ownerJournal(value,0,0),SamechainCodec.ownerJournal(value,1,0));}
    function singleJournal(bytes calldata packet,uint8 role,uint8 action) external pure returns(bytes memory){return SamechainCodec.ownerJournal(SamechainCodec.decodeSingle(packet),role,action);}
    function withdrawalJournal(bytes calldata packet) external pure returns(bytes memory){return SamechainCodec.withdrawalJournal(SamechainCodec.decodeWithdrawal(packet));}
}
contract SamechainCallsVectors {function data(uint256 index) external pure returns(bytes memory){return index==0?SamechainFill2Vectors.data():SamechainCallVectors.data(index);}function proof(bool b) external pure returns(bytes memory){return SamechainCallVectors.proof(b);}}
contract SamechainCallsNativeVectors {function packet(uint256 index) external pure returns(bytes memory){return index==0?SamechainFill2Vectors.packet():SamechainNativeVectors.packet(index);}function journal(uint256 index,bool b) external pure returns(bytes memory){return index==0?SamechainFill2Vectors.journal(b):SamechainNativeVectors.journal(index,b);}}
contract SamechainCallsTest {
    SamechainCallsHarness private harness;SamechainCallsVectors private calls;SamechainCallsNativeVectors private native;
    function _deploy(string memory name) private returns(address deployed){bytes memory code=SamechainCallsVm(address(uint160(uint256(keccak256("hevm cheat code"))))).getCode(name);assembly("memory-safe"){deployed:=create(0,add(code,32),mload(code))}require(deployed!=address(0),"ABI artifact deployment");}
    function setUp() public {harness=SamechainCallsHarness(_deploy("SamechainCalls.t.sol:SamechainCallsHarness"));calls=SamechainCallsVectors(_deploy("SamechainCalls.t.sol:SamechainCallsVectors"));native=SamechainCallsNativeVectors(_deploy("SamechainCalls.t.sol:SamechainCallsNativeVectors"));}
    function testAllNineActualRustCallsDecodeUnderCompilerAuthorityABI() public view {
        for(uint256 i;i<9;++i){
            (bytes32 packetHash,bytes32 proofAHash,bytes32 proofBHash,uint8 role,uint8 action,bytes memory journalA,bytes memory journalB)=harness.decode(calls.data(i));
            require(packetHash==sha256(native.packet(i)),"actual canonical packet changed");
            require(proofAHash==sha256(calls.proof(false)),"actual proof A changed");
            require(keccak256(journalA)==keccak256(native.journal(i,false)),"actual expected journal A");
            if(i==0){require(proofBHash==sha256(calls.proof(true)),"actual proof B changed");require(keccak256(journalB)==keccak256(native.journal(i,true)),"actual expected journal B");}
            else{require(proofBHash==sha256(bytes("")) && journalB.length==0,"unexpected second proof");}
            if(i==1||i==2){require(role==0 && action==i,"single role action words");}
        }
    }
}
