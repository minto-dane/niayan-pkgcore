-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Resolver_Model; use Resolver_Model;
package Resolver_Wire with SPARK_Mode, Pure is
   Header_Size : constant := 300;
   Maximum_Universe_Bytes : constant := Header_Size + Max_Items * 124
      + Max_Nodes * 16 + Max_Rules * 40 + Max_Claims * 104;
   Maximum_Proposal_Bytes : constant := 48 + Max_Items + Max_Steps * 8;
   function Size (U : Universe) return Natural is
     (Header_Size + U.Item_Count * 124 + U.Node_Count * 16
        + U.Rule_Count * 40 + U.Claim_Count * 104);
   procedure Encode (U : Universe; B : out Bytes; Used : out Natural; Status : out Outcome)
      with Global => null;
   procedure Decode (B : Bytes; U : out Universe; Status : out Outcome) with Global => null;
   procedure Encode_Proposal (P : Proposal; Item_Count : Item_ID;
      B : out Bytes; Used : out Natural; Status : out Outcome) with Global => null;
   procedure Decode_Proposal (B : Bytes; Item_Count : Item_ID;
      P : out Proposal; Status : out Outcome) with Global => null;
   -- Big endian, exact length, explicit tags, no enum representation/ABI dump,
   -- no ignored trailer. Hash the entire canonical encoding, including binding.
end Resolver_Wire;
