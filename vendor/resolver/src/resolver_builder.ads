-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Resolver_Model; use Resolver_Model;
package Resolver_Builder with SPARK_Mode, Pure is
   procedure Boolean_Constant (U : in out Universe; Value : Boolean; ID : out Node_ID; Status : out Outcome) with Global => null;
   procedure Presence (U : in out Universe; Item : Item_ID; ID : out Node_ID; Status : out Outcome) with Global => null;
   procedure Negate (U : in out Universe; A : Node_ID; ID : out Node_ID; Status : out Outcome) with Global => null;
   procedure Combine (U : in out Universe; Op : Operator; A, B : Node_ID;
      ID : out Node_ID; Status : out Outcome) with Global => null;
   procedure Require (U : in out Universe; Predicate : Node_ID; Scope : Rule_Scope;
      Origin : Digest; Status : out Outcome) with Global => null;
   -- The caller owns/authenticates U. These are checked builder primitives,
   -- never an API by which the untrusted solver can relax its own problem.
end Resolver_Builder;
