-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Resolver_CNF; with Resolver_Proof;
package Resolver_LRAT with SPARK_Mode is
   Max_Proof_Bytes : constant := 16_777_216;
   procedure Check (F : Resolver_CNF.Formula; Proof : Bytes;
      Workspace : in out Resolver_Proof.Database;
      Accepted : out Boolean; Status : out Outcome; Fuel : in out Natural)
      with Global => null, Post => (if Accepted then Status = OK);
   -- Text LRAT grammar only. Hints are parsed/bounded, but inference is checked
   -- by independent exhaustive RUP/RAT. Binary LRAT and new variables outside
   -- the original DIMACS declaration are rejected, not trusted or truncated.
end Resolver_LRAT;
