-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Resolver_Model; use Resolver_Model;
package Resolver_Verify with SPARK_Mode, Pure is
   Default_Fuel : constant := 50_000_000;
   procedure Check_Selection (U : Universe; S : Selection;
      R : out Report; Fuel : in out Natural)
     with Global => null, Post => not R.Execution_Permit
       and then (if R.Code=Valid_Selection then Well_Formed(U));
   procedure Check_Schedule (U : Universe; Expected_Hash : Digest;
      P : Proposal; R : out Report; Fuel : in out Natural)
     with Global => null, Post => not R.Execution_Permit;
   -- Neither procedure calls or trusts a solver, native package library,
   -- shell, dynamic plugin or proposer-provided claim of completeness.
end Resolver_Verify;
