-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Resolver_Model; use Resolver_Model;
package Resolver_CNF with SPARK_Mode, Pure is
   Max_Variables : constant := Max_Items + Max_Nodes;
   Max_Clauses : constant := 131_072;
   subtype Literal is Integer range -Max_Variables .. Max_Variables;
   type Small_Literals is array (Positive range 1 .. 3) of Literal;
   type Clause is record
      Count : Natural range 0 .. 3 := 0;
      Terms : Small_Literals := (others => 0);
   end record;
   type Clause_Array is array (Positive range 1 .. Max_Clauses) of Clause;
   type Formula is record
      Variables : Natural range 0 .. Max_Variables := 0;
      Count : Natural range 0 .. Max_Clauses := 0;
      Clauses : Clause_Array;
   end record;
   procedure Compile (U : Universe; F : out Formula; Status : out Outcome;
      Fuel : in out Natural) with Global => null;
   procedure Model (U : Universe; S : Selection; Values : out Truth_Array;
      F : Formula; Valid : out Boolean) with Global => null;
   -- Tseitin equivalences + all hard final Boolean rules, pins, permission and
   -- resource conflicts. Capacity and order are checked directly, not encoded.
   -- UNSAT of this relaxation is sound only for this exact, closed universe.
end Resolver_CNF;
