-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Witness with SPARK_Mode, Pure is
   type Fact is (Cluster_Reservation, Resource_Quiesced, Semantic_Health,
                 Data_Backward_Compatible, Isolation_Confirmed);
   type Statement is record
      Kind : Fact := Cluster_Reservation;
      Cluster_ID, Node_ID, Root_ID, Transaction_ID, Boot_ID : Identity := Zero_Identity;
      Plan, Contract : Digest := Zero_Digest;
      Epoch, Token, Issued, Expires : Counter := 0;
   end record;
   subtype Frame is Bytes(1..224);
   function Encode(S : Statement) return Frame with Global=>null;
   procedure Decode(B : Bytes; S : out Statement; Status : out Outcome) with Global=>null;
   function Matches(S, Expected : Statement; Now, Maximum_Age : Counter) return Boolean with Global=>null;
   -- A signed statement proves issuer/bytes, not physical fencing or application
   -- correctness. Observer keys must belong to independently qualified adapters.
end MC_Witness;
