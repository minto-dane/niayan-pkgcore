-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package Pkg_Root_State with SPARK_Mode, Pure is
   type State is record
      Root_ID : Identity := Zero_Identity;
      Generation : Counter := 0;
      Active_Transaction : Identity := Zero_Identity;
      Active_Plan, Accepted_Plan, Package_Set : Digest := Zero_Digest;
   end record;
   subtype Frame is Bytes(1..192);
   function Encode(S : State) return Frame with Global=>null;
   procedure Decode(B : Bytes; S : out State; Status : out Outcome) with Global=>null;
end Pkg_Root_State;
